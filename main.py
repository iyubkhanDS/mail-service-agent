import json
import os
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="A2A Mailroom Agent", version="2.1.0")

incident_ledger: Dict[str, Dict[str, Any]] = {}

class IncidentRequest(BaseModel):
    caseId: str
    recipientId: str
    requestedAction: str
    evidence: str

class ReceiptRequest(BaseModel):
    recipientId: str
    action: str
    timestamp: str
    signature: str

def redact_sensitive_data(text: str) -> str:
    if not text:
        return "[REDACTED]"
    redacted = re.sub(r'(sk-[a-zA-Z0-9]{20,}|password|secret|token|key|confidential)', '[REDACTED]', text, flags=re.IGNORECASE)
    return redacted

@app.middleware("http")
async def add_correlation_and_tracing(request: Request, call_next):
    correlation_id = request.headers.get("x-correlation-id") or request.headers.get("x-request-id") or "default-correlation-id"
    traceparent = request.headers.get("traceparent") or "00-00000000000000000000000000000000-0000000000000000-01"
    
    response = await call_next(request)
    response.headers["x-correlation-id"] = correlation_id
    response.headers["traceparent"] = traceparent
    return response

@app.post("/v2/incidents")
async def process_incident(payload: IncidentRequest):
    if not payload.evidence or not payload.evidence.strip():
        raise HTTPException(
            status_code=422,
            detail="Evidence is required and cannot be empty."
        )

    safe_evidence = redact_sensitive_data(payload.evidence)
    citation = f"Evidence validated and redacted: {safe_evidence}"

    record = {
        "caseId": payload.caseId,
        "recipientId": payload.recipientId,
        "permittedAction": payload.requestedAction,
        "evidenceCitation": citation,
        "status": "PENDING_RECEIPT"
    }
    
    incident_ledger[payload.caseId] = record

    return {
        "status": "PENDING_RECEIPT",
        "caseId": payload.caseId,
        "permittedAction": payload.requestedAction,
        "evidenceCitation": citation,
        "requiredScope": {
            "caseId": payload.caseId,
            "recipientId": payload.recipientId,
            "action": payload.requestedAction
        }
    }

@app.post("/v2/incidents/{case_id}/receipt")
async def verify_receipt(case_id: str, receipt: ReceiptRequest):
    if case_id not in incident_ledger:
        raise HTTPException(
            status_code=404,
            detail="Case ID not found in ledger."
        )
    
    record = incident_ledger[case_id]

    if receipt.recipientId != record["recipientId"]:
        raise HTTPException(
            status_code=403,
            detail="Scope mismatch: Recipient ID does not match case file."
        )

    if receipt.action != record["permittedAction"]:
        raise HTTPException(
            status_code=403,
            detail="Scope mismatch: Action does not match permitted action."
        )

    record["status"] = "COMPLETED"
    incident_ledger[case_id] = record

    return {
        "status": "COMPLETED",
        "caseId": case_id,
        "recipientId": record["recipientId"],
        "actionTaken": record["permittedAction"],
        "evidenceCitation": record["evidenceCitation"]
    }