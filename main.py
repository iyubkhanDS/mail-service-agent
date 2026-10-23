import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from fastapi import FastAPI, Header, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="A2A Mailroom Agent", version="1.0.0")

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

@app.post("/v2/incidents")
async def process_incident(payload: IncidentRequest):
    if not payload.evidence or not payload.evidence.strip():
        raise HTTPException(
            status_code=422,
            detail="Evidence is required and cannot be empty."
        )

    record = {
        "caseId": payload.caseId,
        "recipientId": payload.recipientId,
        "permittedAction": payload.requestedAction,
        "evidenceCitation": f"Evidence validated: {payload.evidence}",
        "status": "PENDING_RECEIPT"
    }
    
    incident_ledger[payload.caseId] = record

    return {
        "status": "PENDING_RECEIPT",
        "caseId": payload.caseId,
        "permittedAction": payload.requestedAction,
        "evidenceCitation": record["evidenceCitation"],
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