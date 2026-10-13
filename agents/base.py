"""Identifier screening and tamper-evident, process-local HMAC audit trail.

The regex screening is a best-effort safeguard, not HIPAA de-identification.
The in-memory chain is not persistent, independently anchored, or SGX-backed.
"""
import copy
import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

PHI_PATTERNS = [
    re.compile(r"\b(?:MRN|mrn)[:#\s-]*\d{4,10}\b", re.IGNORECASE),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b(?:DOB|Date of Birth)[:\s]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", re.IGNORECASE),
    re.compile(r"\b(?:Patient\s+Name|Patient)[:\s]+[A-Z][a-z]+\s+[A-Z][a-z]+\b", re.IGNORECASE),
    re.compile(r"\b(?:John\s+Doe|Jane\s+Smith|Alice\s+Johnson)\b", re.IGNORECASE),
]


class SecurityException(Exception):
    """Raised when identifier screening rejects an input."""


class ResourceLimitExceededException(Exception):
    """Raised when computational parameters exceed safety bounds."""


def assert_no_phi(text: str) -> None:
    if text is None:
        return
    for pattern in PHI_PATTERNS:
        if pattern.search(str(text)):
            raise SecurityException("Potential sensitive identifier detected; request rejected")


class PHIGuard:
    @staticmethod
    def assert_no_phi(text: str) -> None:
        assert_no_phi(text)

    @staticmethod
    def redact_phi(text: str) -> str:
        result = str(text)
        for pattern in PHI_PATTERNS:
            result = pattern.sub("[REDACTED_IDENTIFIER]", result)
        return result


class AuditTrail:
    """Process-local HMAC chain. A missing secret gets a random ephemeral key."""

    _GENESIS = "GENESIS_BLOCK_0000000000000000"
    _SIGNED_FIELDS = ("audit_id", "timestamp", "actor", "actor_tier",
                      "event_type", "payload_hash", "prev_hash")

    def __init__(self, secret_key: Optional[str] = None):
        supplied = secret_key if secret_key is not None else os.getenv("AUDIT_SECRET_KEY")
        if supplied is not None and not supplied:
            raise ValueError("AUDIT_SECRET_KEY must not be empty")
        self.secret_key = supplied.encode("utf-8") if supplied is not None else os.urandom(32)
        self.logs: List[Dict[str, Any]] = []

    def _sign(self, entry: Dict[str, Any]) -> str:
        payload = "|".join(str(entry[field]) for field in self._SIGNED_FIELDS)
        return hmac.new(self.secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def log(self, actor: str, actor_tier: str, event_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        for value in (actor, actor_tier, event_type):
            assert_no_phi(value)
        payload = json.dumps(details, sort_keys=True, allow_nan=False)
        assert_no_phi(payload)
        entry = {
            "audit_id": f"AUDIT-{time.time_ns()}-{len(self.logs) + 1}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "actor_tier": actor_tier,
            "event_type": event_type,
            "payload_hash": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "prev_hash": self.logs[-1]["current_hash"] if self.logs else self._GENESIS,
        }
        entry["current_hash"] = self._sign(entry)
        self.logs.append(entry)
        return copy.deepcopy(entry)

    def verify_integrity(self) -> bool:
        previous = self._GENESIS
        for entry in self.logs:
            try:
                if set(entry) != set(self._SIGNED_FIELDS) | {"current_hash"}:
                    return False
                if not hmac.compare_digest(entry["prev_hash"], previous):
                    return False
                expected = self._sign(entry)
                if not hmac.compare_digest(entry["current_hash"], expected):
                    return False
                previous = entry["current_hash"]
            except (KeyError, TypeError, ValueError):
                return False
        return True

    def get_trail(self) -> List[Dict[str, Any]]:
        return copy.deepcopy(self.logs)


GLOBAL_AUDIT = AuditTrail()


class AuditLogger:
    @staticmethod
    def log(actor: str, actor_tier: str, event_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        return GLOBAL_AUDIT.log(actor, actor_tier, event_type, details)

    @staticmethod
    def get_trail() -> List[Dict[str, Any]]:
        return GLOBAL_AUDIT.get_trail()

    @staticmethod
    def verify_integrity() -> bool:
        return GLOBAL_AUDIT.verify_integrity()


class ActionExecutor:
    @staticmethod
    def execute_with_audit(actor: str, actor_tier: str, action_type: str, fn, *args, **kwargs):
        result = fn(*args, **kwargs)
        AuditLogger.log(actor, actor_tier, action_type, {"status": "SUCCESS"})
        return result
