"""Security, input-parsing and API regression tests."""
import csv

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from agents.api import app
from agents.base import AuditTrail, SecurityException
from agents.models import SystemTaskPayload
from agents.supervisor import SystemSupervisor
from cli import main, parse_csv_bool

SAMPLE = {
    "task_id": "T-01",
    "target_identifier": "TEST-01",
    "primary_metric": 12,
    "secondary_metric": 4,
    "status_descriptor": "NOMINAL",
    "is_critical_flag": False,
}


def test_audit_recomputes_signatures_and_detects_tampering():
    trail = AuditTrail(secret_key="unit-test-key")
    trail.log("operator", "test", "evaluation", {"value": 1})
    trail.log("operator", "test", "evaluation", {"value": 2})
    assert trail.verify_integrity()
    export = trail.get_trail()
    export[0]["event_type"] = "tamper"
    assert trail.verify_integrity(), "export must be a defensive copy"
    trail.logs[0]["event_type"] = "tamper"
    assert not trail.verify_integrity(), "HMAC must be recomputed, not just linked"


def test_missing_secret_uses_random_ephemeral_key(monkeypatch):
    monkeypatch.delenv("AUDIT_SECRET_KEY", raising=False)
    trail_a = AuditTrail()
    trail_b = AuditTrail()
    assert trail_a.secret_key != trail_b.secret_key
    assert len(trail_a.secret_key) == 32


@pytest.mark.parametrize("value,expected", [
    ("False", False), ("false", False), ("0", False), ("", False),
    ("TRUE", True), ("yes", True), ("1", True),
])
def test_parse_csv_bool(value, expected):
    assert parse_csv_bool(value) is expected


def test_bad_csv_boolean_is_rejected():
    with pytest.raises(ValueError):
        parse_csv_bool("sometimes")


def test_csv_false_does_not_trigger_critical_alert(tmp_path):
    source = tmp_path / "input.csv"
    output = tmp_path / "output.csv"
    source.write_text(
        "task_id,target_identifier,primary_metric,secondary_metric,is_critical_flag,status_descriptor\\n"
        "T-2,SAMPLE-2,10,4,False,NOMINAL\\n".replace("\\n", "\n"),
        encoding="utf-8",
    )
    assert main(["batch", "-i", str(source), "-o", str(output)]) == 0
    with output.open(newline="", encoding="utf-8") as fh:
        row = next(csv.DictReader(fh))
    assert row["overall_urgency"] == "ROUTINE"


def test_nan_and_blank_identifiers_rejected():
    with pytest.raises(ValidationError):
        SystemTaskPayload(**{**SAMPLE, "primary_metric": float("nan")})
    with pytest.raises(ValidationError):
        SystemTaskPayload(**{**SAMPLE, "task_id": "  "})


def test_identifier_screening_in_attributes():
    supervisor = SystemSupervisor(model_provider="mock")
    payload = SystemTaskPayload(**{**SAMPLE, "attributes": {"note": "MRN-123456"}})
    with pytest.raises(SecurityException):
        supervisor.process_task(payload)


def test_api_denies_access_until_authenticated(monkeypatch):
    client = TestClient(app)
    monkeypatch.delenv("API_TOKEN", raising=False)
    assert client.post("/api/audit", json=SAMPLE).status_code == 503
    monkeypatch.setenv("API_TOKEN", "test-strong-token")
    assert client.post("/api/audit", json=SAMPLE).status_code == 401
    assert client.get("/api/audit/logs").status_code == 401
    assert client.get("/metrics").status_code == 401
    good = client.post("/api/audit", json=SAMPLE, headers={"x-api-key": "test-strong-token"})
    assert good.status_code == 200
    assert good.json()["overall_urgency"] == "ROUTINE"
    assert client.get("/health").status_code == 200
    assert client.get("/health").json()["hardware_attestation"] is False


def test_api_rejects_identifier_pattern(monkeypatch):
    monkeypatch.setenv("API_TOKEN", "test-strong-token")
    result = TestClient(app).post(
        "/api/audit",
        json={**SAMPLE, "target_identifier": "MRN-123456"},
        headers={"x-api-key": "test-strong-token"},
    )
    assert result.status_code == 400
    assert "MRN-123456" not in result.text
