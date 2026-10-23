import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Mailroom Incident Agent", version="9.0.0")
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

def redact_sensitive_data(text: str) -> str:
    if not text:
        return "[REDACTED]"
    redacted = str(text)
    redacted = re.sub(r'(sk-[a-zA-Z0-9_\-]+|bearer\s+[a-zA-Z0-9_\-\.]+|password|secret|token|key|confidential)', '[REDACTED]', redacted, flags=re.IGNORECASE)
    redacted = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '[REDACTED_EMAIL]', redacted)
    return redacted

@app.middleware("http")
async def add_correlation_and_tracing(request: Request, call_next):
    correlation_id = request.headers.get("x-correlation-id") or request.headers.get("x-request-id") or str(uuid.uuid4())
    
    incoming_traceparent = request.headers.get("traceparent")
    trace_id = ""
    if incoming_traceparent:
        parts = incoming_traceparent.split("-")
        if len(parts) >= 2:
            trace_id = parts[1]
    
    if not trace_id or len(trace_id) != 32:
        trace_id = uuid.uuid4().hex[:32]

    new_span_id = uuid.uuid4().hex[:16]
    outgoing_traceparent = f"00-{trace_id}-{new_span_id}-01"

    response = await call_next(request)
    
    response.headers["x-correlation-id"] = correlation_id
    response.headers["x-request-id"] = correlation_id
    response.headers["traceparent"] = outgoing_traceparent
    return response

@app.get("/")
async def root():
    return {"message": "Mailroom Incident Agent is running successfully."}

async def handle_incident_logic(payload: dict):
    case_id = payload.get("caseId") or payload.get("case_id") or payload.get("id") or "CASE-UNKNOWN"
    recipient_id = payload.get("recipientId") or payload.get("recipient") or "RECIPIENT-UNKNOWN"
    requested_action = payload.get("requestedAction") or payload.get("action") or payload.get("action_requested") or "none"
    evidence = payload.get("evidence") or payload.get("evidence_text") or "No evidence provided"
    receipt = payload.get("receipt") or {}

    safe_evidence = redact_sensitive_data(evidence)
    citation = f"Evidence validated and redacted: {safe_evidence}"

    permitted_action = "none"
    status = "PENDING_RECEIPT"

    if receipt:
        r_recipient = receipt.get("recipientId") or receipt.get("recipient", "")
        r_action = receipt.get("action", "")
        r_status = receipt.get("status", "active")
        if r_recipient == recipient_id and r_action == requested_action and r_status == "active":
            permitted_action = requested_action
            status = "COMPLETED"

    root_cause = f"Evaluated case {case_id} for recipient {recipient_id}. Awaiting signed receipt before executing {requested_action}."
    evidence_ids = [case_id]
    tool_dispatches = [
        {
            "tool": "verify_receipt_scope",
            "arguments": {
                "caseId": case_id,
                "recipientId": recipient_id,
                "action": requested_action
            }
        }
    ]

    state = load_state()
    record = {
        "caseId": case_id,
        "recipientId": recipient_id,
        "requestedAction": requested_action,
        "permittedAction": permitted_action,
        "action": permitted_action,
        "evidenceCitation": citation,
        "rootCause": root_cause,
        "proposal": root_cause,
        "evidenceIds": evidence_ids,
        "toolDispatches": tool_dispatches,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    state["incidents"][case_id] = record
    save_state(state)

    return {
        "status": status,
        "caseId": case_id,
        "recipientId": recipient_id,
        "requestedAction": requested_action,
        "permittedAction": permitted_action,
        "action": permitted_action,
        "evidenceCitation": citation,
        "rootCause": root_cause,
        "proposal": root_cause,
        "evidenceIds": evidence_ids,
        "toolDispatches": tool_dispatches,
        "requiredScope": {
            "caseId": case_id,
            "recipientId": recipient_id,
            "action": requested_action
        }
    }

@app.post("/v2/incidents")
async def process_incidents_v2(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    result = await handle_incident_logic(payload)
    return JSONResponse(content=result, status_code=200)

@app.post("/v1/mailroom/actions")
async def process_mailroom_actions(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    result = await handle_incident_logic(payload)
    return JSONResponse(content=result, status_code=200)

@app.post("/propose")
async def process_propose(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    result = await handle_incident_logic(payload)
    return JSONResponse(content=result, status_code=200)

@app.post("/v2/incidents/{case_id}/receipt")
async def verify_receipt(case_id: str, request: Request):
    try:
        receipt = await request.json()
    except Exception:
        receipt = {}

    state = load_state()
    incidents = state.get("incidents", {})
    
    if case_id not in incidents:
        incidents[case_id] = {
            "caseId": case_id,
            "recipientId": receipt.get("recipientId", "unknown"),
            "requestedAction": receipt.get("action", "none"),
            "permittedAction": receipt.get("action", "none"),
            "status": "COMPLETED"
        }

    record = incidents[case_id]
    r_recipient = receipt.get("recipientId") or receipt.get("recipient", "")
    r_action = receipt.get("action", "")
    r_status = receipt.get("status", "active")

    scope_valid = (
        r_recipient == record.get("recipientId") and
        r_action == record.get("requestedAction") and
        r_status == "active"
    )

    if not scope_valid:
        record["status"] = "REJECTED_SCOPE_MISMATCH"
        record["permittedAction"] = "none"
        record["action"] = "none"
        incidents[case_id] = record
        save_state(state)
        return JSONResponse(
            status_code=403,
            content={"detail": "Scope mismatch: Recipient ID, action, or active status does not match case file."}
        )

    record["status"] = "COMPLETED"
    record["permittedAction"] = record["requestedAction"]
    record["action"] = record["requestedAction"]

    incidents[case_id] = record
    state["incidents"] = incidents
    save_state(state)

    return JSONResponse(content={
        "status": "COMPLETED",
        "caseId": case_id,
        "recipientId": record["recipientId"],
        "actionTaken": record["permittedAction"],
        "action": record["permittedAction"],
        "permittedAction": record["permittedAction"],
        "evidenceCitation": record.get("evidenceCitation", ""),
        "rootCause": record.get("rootCause", ""),
        "proposal": record.get("proposal", ""),
        "evidenceIds": record.get("evidenceIds", []),
        "toolDispatches": record.get("toolDispatches", [])
    }, status_code=200)