"""Authenticated API for rule-based simulation; not hardware remote attestation."""
import hmac
import os

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .base import AuditLogger, SecurityException
from .models import SystemTaskPayload
from .supervisor import SystemSupervisor

supervisor = SystemSupervisor(model_provider="mock")

app = FastAPI(
    title="Secure Enclave Threshold Evaluation API",
    description="Rule-based demonstration only. Does not verify Intel SGX or AMD SEV-SNP attestation reports.",
    version="3.0.1",
)


def require_api_token(x_api_key: str = Header(default="")) -> None:
    expected = os.getenv("API_TOKEN")
    if not expected:
        raise HTTPException(status_code=503, detail="API_TOKEN is not configured")
    if not hmac.compare_digest(x_api_key.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Authentication required")


@app.get("/health")
def health():
    return {"status": "HEALTHY", "service": "secure-enclave-sgx-attestation",
            "mode": "threshold-demonstration", "hardware_attestation": False}


@app.get("/metrics", dependencies=[Depends(require_api_token)])
def metrics():
    return {
        "dossiers_processed_total": len(supervisor.dossier_registry),
        "audit_blocks_total": len(AuditLogger.get_trail()),
        "audit_chain_valid": AuditLogger.verify_integrity(),
    }


@app.post("/api/audit", dependencies=[Depends(require_api_token)])
def api_audit(payload: SystemTaskPayload):
    try:
        return supervisor.process_task(payload).to_dict()
    except SecurityException as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class ChatRequest(BaseModel):
    query: str


@app.post("/api/chat", dependencies=[Depends(require_api_token)])
def api_chat(req: ChatRequest):
    try:
        return {"response": supervisor.query_supervisory_chat(req.query)}
    except (SecurityException, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/audit/logs", dependencies=[Depends(require_api_token)])
def api_audit_logs():
    return {"audit_trail": AuditLogger.get_trail(),
            "verified": AuditLogger.verify_integrity()}
