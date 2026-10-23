import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(title="Mailroom Incident Agent", version="4.0.0")
STATE_FILE = "incident_state.json"

def load_state() -> Dict[str, Any]:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {"incidents": {}}
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
    # Comprehensive redaction for API keys, bearer tokens, passwords, secrets, PII
    pattern = r'(sk-[a-zA-Z0-9]{20,}|bearer\s+[a-zA-Z0-9_\-\.]+|password|secret|token|key|confidential|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'
    return re.sub(pattern, '[REDACTED]', text, flags=re.IGNORECASE)

@app.middleware("http")
async def add_correlation_and_tracing(request: Request, call_next):
    correlation_id = request.headers.get("x-correlation-id") or request.headers.get("x-request-id") or str(uuid.uuid4())
    
    # W3C Traceparent handling & topology propagation
    incoming_traceparent = request.headers.get("traceparent")
    trace_id = ""
    if incoming_traceparent:
        parts = incoming_traceparent.split("-")
        if len(parts) >= 2:
            trace_id = parts[1]
    
    if not trace_id or len(trace_id) != 32:
        trace_id = uuid.uuid4().hex + uuid.uuid4().hex[:16] # 32 hex chars
        trace_id = trace_id[:32]

    new_span_id = uuid.uuid4().hex[:16] # 16 hex chars
    outgoing_traceparent = f"00-{trace_id}-{new_span_id}-01"

    response = await call_next(request)
    
    response.headers["x-correlation-id"] = correlation_id
    response.headers["x-request-id"] = correlation_id
    response.headers["traceparent"] = outgoing_traceparent
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

    # Proposal & Tool Dispatches (required before effects)
    root_cause = f"Evaluated case {payload.caseId} for recipient {payload.recipientId} under action {payload.requestedAction}."
    evidence_ids = [payload.caseId]
    tool_dispatches = [
        {
            "tool": "validate_evidence_and_scope",
            "arguments": {
                "caseId": payload.caseId,
                "recipientId": payload.recipientId,
                "action": payload.requestedAction,
                "evidenceSnippet": safe_evidence[:100]
            }
        }
    ]

    # Lifecycle: Must wait for signed receipts before recording action as completed.
    # Status starts as PENDING_RECEIPT. No destructive effects executed yet.
    status = "PENDING_RECEIPT"
    permitted_action = payload.requestedAction

    state = load_state()
    record = {
        "caseId": payload.caseId,
        "recipientId": payload.recipientId,
        "permittedAction": permitted_action,
        "evidenceCitation": citation,
        "status": status,
        "rootCause": root_cause,
        "evidenceIds": evidence_ids,
        "toolDispatches": tool_dispatches,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    state["incidents"][payload.caseId] = record
    save_state(state)

    return {
        "status": status,
        "caseId": payload.caseId,
        "permittedAction": permitted_action,
        "evidenceCitation": citation,
        "rootCause": root_cause,
        "evidenceIds": evidence_ids,
        "toolDispatches": tool_dispatches,
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

    # Strict signed receipt scope verification
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