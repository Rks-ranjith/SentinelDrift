"""
rules.py

Cold-start rule-based detection engine inspired by
ModSecurity Core Rule Set

RuleEngine.score_request evaluates requests against 10
regex-based _PatternRules (LOG4SHELL 0.95, COMMAND_
INJECTION 0.90, SQL_INJECTION 0.85, XXE_INJECTION 0.82,
XSS 0.80, FILE_INCLUSION 0.75, SSRF 0.70, CRLF_INJECTION
0.65, PATH_TRAVERSAL 0.60, OPEN_REDIRECT 0.55),
double-encoding detection (0.40), scanner user-agent
signature matching (0.35), and 2 _ThresholdRules
(RATE_ANOMALY >100 req/min 0.30, HIGH_ERROR_RATE >50%
0.25). Final score takes the highest match plus 0.05
boost per additional rule, capped at 1.0. Returns a
RuleResult with threat_score, severity, matched_rules,
and component_scores

Connects to:
  core/features/
    patterns       - compiled regex patterns (SQLI,
                      XSS, LOG4SHELL, CRLF_INJECTION,
                      OPEN_REDIRECT, etc.)
  core/features/
    signatures     - SCANNER_USER_AGENTS list
  core/detection/
    ensemble       - classify_severity
  core/ingestion/
    parsers        - ParsedLogEntry
"""

import re
from dataclasses import dataclass, field
from typing import NamedTuple

from app.core.features.patterns import (
    COMMAND_INJECTION,
    CRLF_INJECTION,
    DOUBLE_ENCODED,
    FILE_INCLUSION,
    LOG4SHELL,
    OPEN_REDIRECT,
    PATH_TRAVERSAL,
    SQLI,
    SSRF,
    XSS,
    XXE_INJECTION,
)
from app.core.features.signatures import SCANNER_USER_AGENTS
from app.core.detection.ensemble import classify_severity as _classify_severity
from app.core.ingestion.parsers import ParsedLogEntry


class _PatternRule(NamedTuple):
    """
    A regex based detection rule applied to the request URI
    """

    name: str
    pattern: re.Pattern[str]
    score: float


class _ThresholdRule(NamedTuple):
    """
    A threshold-based detection rule applied to a windowed feature
    """

    name: str
    feature_key: str
    threshold: float
    score: float


@dataclass(frozen=True, slots=True)
class RuleExclusion:
    """
    Defines a rule bypass/exclusion logic for paths and/or source IPs.
    """

    rule_name: str  # Rule name to bypass (e.g. "SQL_INJECTION", "RATE_ANOMALY") or "*" for all rules
    paths: list[str] = field(default_factory=list)  # Substring paths to bypass
    ips: list[str] = field(default_factory=list)  # Source IPs to bypass


_PATTERN_RULES: list[_PatternRule] = [
    _PatternRule("LOG4SHELL", LOG4SHELL, 0.95),
    _PatternRule("COMMAND_INJECTION", COMMAND_INJECTION, 0.90),
    _PatternRule("SQL_INJECTION", SQLI, 0.85),
    _PatternRule("XXE_INJECTION", XXE_INJECTION, 0.82),
    _PatternRule("XSS", XSS, 0.80),
    _PatternRule("FILE_INCLUSION", FILE_INCLUSION, 0.75),
    _PatternRule("SSRF", SSRF, 0.70),
    _PatternRule("CRLF_INJECTION", CRLF_INJECTION, 0.65),
    _PatternRule("PATH_TRAVERSAL", PATH_TRAVERSAL, 0.60),
    _PatternRule("OPEN_REDIRECT", OPEN_REDIRECT, 0.55),
]

_THRESHOLD_RULES: list[_ThresholdRule] = [
    _ThresholdRule("RATE_ANOMALY", "req_count_1m", 100.0, 0.30),
    _ThresholdRule("HIGH_ERROR_RATE", "error_rate_5m", 0.5, 0.25),
]

_DOUBLE_ENCODING_SCORE = 0.40
_SCANNER_UA_SCORE = 0.35
_BOOST_PER_ADDITIONAL_RULE = 0.05


@dataclass(frozen=True, slots=True)
class RuleResult:
    """
    Output of the rule-based detection engine for a single request.
    """

    threat_score: float
    severity: str
    matched_rules: list[str] = field(default_factory=list)
    component_scores: dict[str, float] = field(default_factory=dict)


class RuleEngine:
    """
    Cold-start rule-based detection engine inspired by ModSecurity CRS.
    Scores requests using pattern matching, signature detection,
    and behavioral thresholds from windowed features
    """

    def __init__(self, exclusions: list[RuleExclusion] | None = None) -> None:
        self.exclusions = exclusions or []

    def _is_excluded(self, rule_name: str, ip: str, path: str) -> bool:
        """
        Check whether a specific rule should be bypassed for a given IP/path.
        """
        for exc in self.exclusions:
            if exc.rule_name == rule_name or exc.rule_name == "*":
                ip_match = not exc.ips or (ip in exc.ips)
                path_match = not exc.paths or any(p in path for p in exc.paths)
                if ip_match and path_match:
                    return True
        return False

    def score_request(
        self,
        features: dict[str, int | float | bool | str],
        entry: ParsedLogEntry,
    ) -> RuleResult:
        """
        Evaluate all rules against a request and return a composite score.
        """
        matched: list[tuple[str, float]] = []

        uri = entry.path
        if entry.query_string:
            uri = f"{entry.path}?{entry.query_string}"

        for rule in _PATTERN_RULES:
            if not self._is_excluded(rule.name, entry.ip, entry.path):
                if rule.pattern.search(uri):
                    matched.append((rule.name, rule.score))

        if not self._is_excluded("DOUBLE_ENCODING", entry.ip, entry.path):
            if DOUBLE_ENCODED.search(uri):
                matched.append(("DOUBLE_ENCODING", _DOUBLE_ENCODING_SCORE))

        if not self._is_excluded("SCANNER_UA", entry.ip, entry.path):
            ua_lower = entry.user_agent.lower()
            if any(sig in ua_lower for sig in SCANNER_USER_AGENTS):
                matched.append(("SCANNER_UA", _SCANNER_UA_SCORE))

        for trule in _THRESHOLD_RULES:
            if not self._is_excluded(trule.name, entry.ip, entry.path):
                value = features.get(trule.feature_key, 0)
                if isinstance(value, int | float) and value > trule.threshold:
                    matched.append((trule.name, trule.score))

        if not matched:
            return RuleResult(threat_score=0.0, severity="LOW")

        scores = sorted([s for _, s in matched], reverse=True)
        threat_score = min(
            scores[0] + _BOOST_PER_ADDITIONAL_RULE * (len(scores) - 1),
            1.0,
        )

        return RuleResult(
            threat_score=threat_score,
            severity=_classify_severity(threat_score),
            matched_rules=[name for name, _ in matched],
            component_scores=dict(matched),
        )
