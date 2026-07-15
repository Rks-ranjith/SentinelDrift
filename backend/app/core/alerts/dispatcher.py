"""
dispatcher.py

Alert dispatcher routing scored threat events to storage,
Redis pub/sub, and structured logging

AlertDispatcher.dispatch receives a ScoredRequest from the
pipeline, classifies severity via classify_severity, logs
every event, and for MEDIUM+ severity persists to
PostgreSQL via create_threat_event and publishes a
WebSocketAlert JSON payload to the ALERTS_CHANNEL for
real-time WebSocket relay

Connects to:
  core/alerts/__init__ - ALERTS_CHANNEL
  core/detection/
    ensemble           - classify_severity
  core/ingestion/
    pipeline           - ScoredRequest dataclass
  schemas/websocket    - WebSocketAlert model
  services/threat_
    service            - create_threat_event
"""

import asyncio
import logging

import httpx
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
)

from app.config import settings
from app.core.alerts import ALERTS_CHANNEL
from app.core.detection.ensemble import classify_severity
from app.core.ingestion.pipeline import ScoredRequest
from app.schemas.websocket import WebSocketAlert
from app.services.threat_service import create_threat_event

logger = logging.getLogger(__name__)


class AlertDispatcher:
    """
    Routes scored threat events to storage, pub/sub,
    and structured logging

    MEDIUM+ severity events are persisted to PostgreSQL
    and published to the Redis alerts channel for
    WebSocket relay. HIGH severity events are additionally
    dispatched to a configured webhook. All events are logged.
    """

    def __init__(
        self,
        redis_client: aioredis.Redis[str],
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._redis = redis_client
        self._session_factory = session_factory
        self._webhook_client = (
            httpx.AsyncClient(timeout=5.0) if settings.webhook_url else None
        )

    async def close(self) -> None:
        """Close external connections."""
        if self._webhook_client:
            await self._webhook_client.aclose()

    async def dispatch(self, scored: ScoredRequest) -> None:
        """
        Handle a scored request from the pipeline's
        dispatch stage
        """
        severity = classify_severity(scored.final_score)

        logger.info(
            "threat_event severity=%s score=%.2f mode=%s ip=%s path=%s rules=%s",
            severity,
            scored.final_score,
            scored.detection_mode,
            scored.entry.ip,
            scored.entry.path,
            scored.rule_result.matched_rules,
        )

        if severity in ("HIGH", "MEDIUM"):
            await self._store_event(scored)
            await self._publish_alert(scored, severity)

        if severity == "HIGH" and self._webhook_client and settings.webhook_url:
            # Fire and forget the webhook to avoid blocking pipeline
            asyncio.create_task(self._send_webhook(scored, severity))

    async def _store_event(self, scored: ScoredRequest) -> None:
        """
        Persist the scored request as a threat event
        in PostgreSQL
        """
        async with self._session_factory() as session:
            await create_threat_event(session, scored)
            await session.commit()

    async def _publish_alert(
        self,
        scored: ScoredRequest,
        severity: str,
    ) -> None:
        """
        Publish a real-time alert to the Redis pub/sub
        channel
        """
        alert = WebSocketAlert(
            timestamp=scored.entry.timestamp,
            source_ip=scored.entry.ip,
            request_method=scored.entry.method,
            request_path=scored.entry.path,
            threat_score=scored.final_score,
            severity=severity,
            component_scores={
                **scored.rule_result.component_scores,
                **(scored.ml_scores or {}),
            },
        )
        await self._redis.publish(ALERTS_CHANNEL, alert.model_dump_json())

    async def _send_webhook(self, scored: ScoredRequest, severity: str) -> None:
        """
        Send a webhook notification to Discord/Slack
        """
        if not self._webhook_client or not settings.webhook_url:
            return

        payload = {
            "content": f"🚨 **HIGH Severity Threat Detected** 🚨",
            "embeds": [
                {
                    "title": "Threat Details",
                    "color": 16711680,  # Red
                    "fields": [
                        {"name": "Source IP", "value": scored.entry.ip, "inline": True},
                        {"name": "Score", "value": f"{scored.final_score:.4f}", "inline": True},
                        {"name": "Method", "value": scored.entry.method, "inline": True},
                        {"name": "Path", "value": scored.entry.path, "inline": False},
                        {"name": "Rules Matched", "value": ", ".join(scored.rule_result.matched_rules) or "None", "inline": False},
                    ]
                }
            ]
        }
        
        try:
            response = await self._webhook_client.post(settings.webhook_url, json=payload)
            response.raise_for_status()
            logger.debug("Webhook dispatched successfully for IP %s", scored.entry.ip)
        except Exception as e:
            logger.error("Failed to dispatch webhook: %s", e)
