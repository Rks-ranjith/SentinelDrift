# SentinelDrift

An AI-powered HTTP threat detection engine — my own rework built incrementally on top of the original [ai-threat-detection](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/ai-threat-detection) project by CarterPerez-dev.

This repo tracks **only the backend** as I rewrite and extend it piece by piece. Frontend and infra will be added once I have meaningfully reworked them.

---

## What it does

- Parses raw nginx access logs in real time
- Extracts 35-dimensional feature vectors per request
- Scores requests through a 3-model ML ensemble (Autoencoder + Random Forest + Isolation Forest)
- Applies a rule engine (ModSecurity CRS-inspired patterns: SQLi, XSS, path traversal, command injection, Log4Shell, SSRF)
- Dispatches alerts over WebSocket with severity scoring

---

## My changes (Changelog)

### Session 2
- Added a "Generate Bypass Rule" feature to the frontend `ThreatDetail` modal. It generates ready-to-use Python snippets of the `RuleExclusion` dataclass to easily whitelist false-positives by IP and path.

### Session 1
- Renamed project from AngelusVigil to **SentinelDrift** across all backend source files
- Removed all inline author annotations from the codebase
- Implemented RuleExclusion dataclass in rules.py — allows per-IP and per-path WAF bypass rules (false-positive whitelisting)
- Added 3 new unit tests for the exclusion engine in test_detection.py

---

## Attribution

This project is a personal fork and educational rework of the original
[AI-Powered Threat Detection Engine](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/ai-threat-detection)
by **CarterPerez-dev**. All original credit goes to them. My changes are documented in the Changelog above.

---

## Stack

- Python 3.14+ / FastAPI / SQLAlchemy / Alembic
- PyTorch, scikit-learn, ONNX Runtime
- Redis, PostgreSQL, MLflow
- pytest (239 tests passing)
