"""
test_dispatcher.py

Tests for the AlertDispatcher webhook notification feature.
Verifies that HIGH severity threats trigger a webhook POST,
MEDIUM severity does not, and missing webhook_url is a no-op.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.config import settings
from app.core.alerts.dispatcher import AlertDispatcher
from app.core.detection.rules import RuleResult
from app.core.enrichment.geoip import GeoResult
from app.core.ingestion.parsers import ParsedLogEntry
from app.core.ingestion.pipeline import ScoredRequest


def _make_session_factory() -> MagicMock:
    """
    Return a MagicMock that behaves like an async_sessionmaker:
    calling it returns an async context manager that yields a
    mock session.
    """
    mock_session = AsyncMock()
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_session
    ctx.__aexit__.return_value = None
    factory = MagicMock(return_value=ctx)
    return factory


def _make_scored(final_score: float = 0.95) -> ScoredRequest:
    return ScoredRequest(
        features={"req_count_1m": 10},
        feature_vector=[0.1, 0.2, 0.3],
        geo=GeoResult(country="US", city="New York", lat=40.7, lon=-74.0),
        entry=ParsedLogEntry(
            ip="192.168.1.100",
            timestamp="2024-01-01T12:00:00Z",
            method="POST",
            path="/admin/login",
            query_string="",
            status_code=200,
            response_size=1024,
            referer="",
            user_agent="BadBot",
            raw_line="",
        ),
        rule_result=RuleResult(
            matched_rules=["SQL_INJECTION"],
            component_scores={"sql_injection": 0.9},
            threat_score=0.9,
            severity="HIGH",
        ),
        ml_scores={"autoencoder": 0.8},
        final_score=final_score,
        detection_mode="ensemble",
    )


@pytest.mark.asyncio
async def test_dispatcher_sends_webhook_for_high_severity(monkeypatch):
    """Webhook should fire when severity is HIGH and webhook_url is set."""
    monkeypatch.setattr(settings, "webhook_url", "https://discord.com/api/webhooks/test")

    mock_redis = AsyncMock()
    session_factory = _make_session_factory()
    scored = _make_scored(final_score=0.95)

    with patch(
        "app.core.alerts.dispatcher.settings", settings
    ), patch(
        "app.services.threat_service.create_threat_event", new_callable=AsyncMock
    ), patch(
        "httpx.AsyncClient.post", new_callable=AsyncMock
    ) as mock_post:
        mock_post.return_value.raise_for_status = MagicMock()
        dispatcher = AlertDispatcher(mock_redis, session_factory)

        await dispatcher.dispatch(scored)
        # Give the fire-and-forget task a moment to run
        await asyncio.sleep(0.05)

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args.kwargs
        payload = call_kwargs["json"]
        assert "HIGH Severity Threat Detected" in payload["content"]
        assert payload["embeds"][0]["fields"][0]["value"] == "192.168.1.100"

        await dispatcher.close()


@pytest.mark.asyncio
async def test_dispatcher_no_webhook_for_medium_severity(monkeypatch):
    """Webhook should NOT fire when severity is MEDIUM."""
    monkeypatch.setattr(settings, "webhook_url", "https://discord.com/api/webhooks/test")

    mock_redis = AsyncMock()
    session_factory = _make_session_factory()
    scored = _make_scored(final_score=0.6)  # MEDIUM

    with patch(
        "app.core.alerts.dispatcher.settings", settings
    ), patch(
        "app.services.threat_service.create_threat_event", new_callable=AsyncMock
    ), patch(
        "httpx.AsyncClient.post", new_callable=AsyncMock
    ) as mock_post:
        dispatcher = AlertDispatcher(mock_redis, session_factory)

        await dispatcher.dispatch(scored)
        await asyncio.sleep(0.05)

        mock_post.assert_not_called()
        await dispatcher.close()


@pytest.mark.asyncio
async def test_dispatcher_no_webhook_if_unconfigured(monkeypatch):
    """Webhook should NOT fire when webhook_url is None."""
    monkeypatch.setattr(settings, "webhook_url", None)

    mock_redis = AsyncMock()
    session_factory = _make_session_factory()
    scored = _make_scored(final_score=0.95)  # HIGH

    with patch(
        "app.core.alerts.dispatcher.settings", settings
    ), patch(
        "app.services.threat_service.create_threat_event", new_callable=AsyncMock
    ), patch(
        "httpx.AsyncClient.post", new_callable=AsyncMock
    ) as mock_post:
        dispatcher = AlertDispatcher(mock_redis, session_factory)

        await dispatcher.dispatch(scored)
        await asyncio.sleep(0.05)

        mock_post.assert_not_called()
        await dispatcher.close()
