"""
FastAPI REST API Server for EnclaveGuard: Intel SGX / AMD SEV Remote Attestation & Quoting Agent.
"""
from typing import Dict, Any
import hmac
import os
from .models import FrontierPayload
from .agents import EnclaveGuardCoordinator

coordinator = EnclaveGuardCoordinator()


def create_app():
    try:
        from fastapi import FastAPI, Depends, Header, HTTPException
        from pydantic import BaseModel, Field

        app = FastAPI(
            title="EnclaveGuard: Intel SGX / AMD SEV Remote Attestation & Quoting Agent",
            description="Legacy numerical threshold demonstration; does not perform cryptographic SGX/SEV attestation.",
            version="2.0.0-FRONTIER",
        )

        def require_api_token(x_api_key: str = Header(default="")):
            expected = os.getenv("API_TOKEN")
            if not expected:
                raise HTTPException(status_code=503, detail="API_TOKEN is not configured")
            if not hmac.compare_digest(x_api_key.encode("utf-8"), expected.encode("utf-8")):
                raise HTTPException(status_code=401, detail="Authentication required")

        class TaskRequest(BaseModel):
            task_id: str = "TASK-2026-001"
            target_identifier: str = "TARGET-BIO-KEY"
            primary_metric: float = Field(default=28.5, allow_inf_nan=False)
            secondary_metric: float = Field(default=14.2, allow_inf_nan=False)
            status_descriptor: str = "DISCORDANT_ANOMALY"
            is_critical_flag: bool = True
            attributes: Dict[str, Any] = {}

        class ChatRequest(BaseModel):
            query: str

        @app.get("/health")
        def health():
            return {"status": "HEALTHY", "system": "secure-enclave-sgx-attestation", "domain": "Privacy-Preserving Federated Healthcare & FHE", "version": "2.0.0-FRONTIER"}

        @app.post("/api/audit", dependencies=[Depends(require_api_token)])
        def api_audit(req: TaskRequest):
            payload = FrontierPayload(
                task_id=req.task_id,
                target_identifier=req.target_identifier,
                primary_metric=req.primary_metric,
                secondary_metric=req.secondary_metric,
                status_descriptor=req.status_descriptor,
                is_critical_flag=req.is_critical_flag,
                attributes=req.attributes,
            )
            return coordinator.process(payload)

        @app.post("/api/chat", dependencies=[Depends(require_api_token)])
        def api_chat(req: ChatRequest):
            return {"response": coordinator.query_supervisory_chat(req.query)}

        return app
    except ImportError:
        return None
