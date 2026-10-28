"""Shared data models: normalized Event (input) and Alert (output)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


@dataclass
class Event:
    """One normalized security-relevant log record.

    kind is one of: AUTH_FAIL, AUTH_OK, INVALID_USER, SSH_PROBE, SUDO_FAIL,
    PRIV_CMD, ACCOUNT_NEW, ACCOUNT_PRIV, ACCOUNT_LOCKED, LOG_CLEARED,
    PERSISTENCE, WEB_REQ, FW_BLOCK.
    """
    ts: datetime
    kind: str
    service: str
    host: str = ""
    user: Optional[str] = None
    ip: Optional[str] = None
    detail: str = ""
    extra: dict = field(default_factory=dict)
    raw: str = ""


@dataclass
class Alert:
    rule: str
    title: str
    severity: str
    key: str
    first_seen: datetime
    last_seen: datetime
    description: str = ""
    mitre: str = ""
    recommendation: str = ""
    ip: Optional[str] = None
    user: Optional[str] = None
    count: int = 1
    evidence: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "ip": self.ip,
            "user": self.user,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(timespec="seconds"),
            "last_seen": self.last_seen.isoformat(timespec="seconds"),
            "mitre_attack": self.mitre,
            "recommendation": self.recommendation,
            "evidence": list(self.evidence),
        }
