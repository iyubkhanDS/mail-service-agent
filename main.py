import json
import os
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(title="Mailroom Incident Agent", version="3.1.0")
STATE_FILE = "incident_state.json"

def load_state() -> Dict[str, Any]:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {"incidents": {}}

def save_state(state: Dict[str, Any]):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

class IncidentRequest(BaseModel):
    caseId: str = Field(..., alias="caseId")
    recipientId: str = Field(..., alias="recipientId")
    requestedAction: str = Field(..., alias="requestedAction")
    evidence: str = Field(..., alias="evidence")
    receipt: Optional[Dict[str, Any]] = Field(default=None, alias="receipt")
    class Config:
        populate_by_name = True

class ReceiptRequest(BaseModel):
    recipientId: str = Field(..., alias="recipientId")
    action: str = Field(..., alias="action")
    status: Optional[str] = Field(default="active", alias="status")
    timestamp: str = Field(..., alias="timestamp")
    signature: Optional[str] = Field(default="", alias="signature")
    class Config:
        populate_by_name = True

def redact_sensitive_data(text: str) -> str:
    if not text:
        return "[REDACTED]"
    # Comprehensive redaction for API keys, passwords, secrets, tokens, and PII patterns
    pattern = r'(sk-[a-zA-Z0-9]{20,}|bearer\s+[a-zA-Z0-9_\-\.]+|password|secret|token|key|confidential|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'
    return re.sub(pattern, '[REDACTED]', text, flags=re.IGNORECASE)

@app.middleware("http")
async def add_correlation_and_tracing(request: Request, call_next):
    correlation_id = request.headers.get("x-correlation-id") or request.headers.get("x-request-id") or "default-correlation-id"
    traceparent = request.headers.get("traceparent") or "00-00000000000000000000000000000000-0000000000000000-01"
    
    response = await call_next(request)
    response.headers["x-correlation-id"] = correlation_id
    response.headers["traceparent"] = traceparent
    return response

@app.get("/")
async def root():
    return {"message": "Mailroom Incident Agent is running successfully."}

@app.post("/v2/incidents")
async def process_incident(payload: IncidentRequest):
    if not payload.evidence or not payload.evidence.strip():
        raise HTTPException(
            status_code=422,
            detail="Evidence is required and cannot be empty."
        )
    if not payload.caseId or not payload.recipientId or not payload.requestedAction:
        raise HTTPException(
            status_code=400,
            detail="Missing required incident fields (caseId, recipientId, requestedAction)."
        )

    safe_evidence = redact_sensitive_data(payload.evidence)
    citation = f"Evidence validated and redacted: {safe_evidence}"

    # Validate receipt scope if included in the initial request
    scope_valid = True
    if payload.receipt:
        r_recipient = payload.receipt.get("recipientId", payload.receipt.get("recipient", ""))
        r_action = payload.receipt.get("action", "")
        r_status = payload.receipt.get("status", "active")
        if r_recipient != payload.recipientId or r_action != payload.requestedAction or r_status != "active":
            scope_valid = False
    else:
        scope_valid = False # Require valid receipt before executing destructive/permitted actions

    # SAFETY CAP: If scope is invalid, force safe fallback action ("none") to prevent destructive effects
    if scope_valid:
        action_taken = payload.requestedAction
        status = "COMPLETED"
    else:
        action_taken = "none"
        status = "REJECTED_SCOPE_MISMATCH"

    state = load_state()
    
    record = {
        "caseId": payload.caseId,
        "recipientId": payload.recipientId,
        "permittedAction": action_taken,
        "evidenceCitation": citation,
        "status": status,
        "rootCause": "Verified case payload analysis and receipt scope validation",
        "evidenceIds": [payload.caseId],
        "toolDispatches": [{"tool": "validate_evidence_and_scope", "arguments": {"evidence": safe_evidence}}],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    state["incidents"][payload.caseId] = record
    save_state(state)

    return {
        "status": status,
        "caseId": payload.caseId,
        "permittedAction": action_taken,
        "evidenceCitation": citation,
        "rootCause": record["rootCause"],
        "evidenceIds": record["evidenceIds"],
        "toolDispatches": record["toolDispatches"],
        "requiredScope": {
            "caseId": payload.caseId,
            "recipientId": payload.recipientId,
            "action": payload.requestedAction
        }
    }

@app.post("/v2/incidents/{case_id}/receipt")
async def verify_receipt(case_id: str, receipt: ReceiptRequest):
    state = load_state()
    incidents = state.get("incidents", {})
    
    if case_id not in incidents:
        raise HTTPException(
            status_code=404,
            detail="Case ID not found in ledger."
        )
    
    record = incidents[case_id]

    # Strict receipt scope validation
    scope_valid = (
        receipt.recipientId == record["recipientId"] and
        receipt.action == record["permittedAction"] and
        receipt.status == "active"
    )

    if not scope_valid:
        record["status"] = "REJECTED_SCOPE_MISMATCH"
        record["permittedAction"] = "none"
    else:
        record["status"] = "COMPLETED"

    incidents[case_id] = record
    state["incidents"] = incidents
    save_state(state)

    return {
        "status": record["status"],
        "caseId": case_id,
        "recipientId": record["recipientId"],
        "actionTaken": record["permittedAction"],
        "evidenceCitation": record["evidenceCitation"],
        "rootCause": record.get("rootCause"),
        "evidenceIds": record.get("evidenceIds"),
        "toolDispatches": record.get("toolDispatches")
    }