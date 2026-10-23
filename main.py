import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from fastapi import FastAPI, Header, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="A2A Mailroom Agent", version="1.0.0")
STATE_FILE = "mailroom_state.json"

def load_state() -> Dict[str, Any]:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {"processed_cases": {}, "tasks": {}}

def save_state(state: Dict[str, Any]):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

# Authentication Dependency
def verify_bearer_token(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Bearer token.")
    token = authorization.split(" ")[1]
    if not token:
        raise HTTPException(status_code=401, detail="Invalid token.")
    return token

# Protocol & Media Type Validation Dependency
async def validate_a2a_request(request: Request, a2a_version: Optional[str] = Header(None, alias="A2A-Version")):
    if request.method == "POST":
        content_type = request.headers.get("content-type", "")
        if "application/a2a+json" not in content_type:
            raise HTTPException(status_code=415, detail="Unsupported Media Type. Must be application/a2a+json.")
    
    if a2a_version and a2a_version not in ["1.0", "1.1"]:
        raise HTTPException(status_code=400, detail="Unsupported A2A version.")
    return True

@app.get("/")
async def root():
    return {"message": "A2A Mailroom Agent is running successfully!"}

@app.get("/.well-known/agent-card.json")
async def agent_card():
    card = {
        "name": "a2a-mailroom-agent",
        "description": "An autonomous mailroom agent that evaluates case files, verifies recipient scope and signed receipts, and executes permitted actions.",
        "version": "1.0.0",
        "protocolVersion": "1.0",
        "url": "https://a2a-invoice-agent-f0r3.onrender.com/a2a/",
        "modes": ["sync", "async"],
        "capabilities": {
            "streaming": False,
            "pushNotifications": False
        },
        "skills": [
            {
                "id": "mailroom_processing",
                "name": "Mailroom Case Processing",
                "description": "Evaluate case files, verify recipient scope in signed receipts, and prevent misrouted or stale actions.",
                "tags": ["mailroom", "case-file", "receipt-validation"]
            }
        ]
    }
    return JSONResponse(content=card, media_type="application/a2a+json")

@app.get("/.well-known/agent.json")
async def agent_json_alias():
    return await agent_card()

@app.get("/tasks", dependencies=[Depends(verify_bearer_token)])
async def list_tasks():
    state = load_state()
    tasks_list = list(state.get("tasks", {}).values())
    return JSONResponse(content={"tasks": tasks_list}, media_type="application/a2a+json")

@app.get("/tasks/{task_id}", dependencies=[Depends(verify_bearer_token)])
async def get_task(task_id: str):
    state = load_state()
    task = state.get("tasks", {}).get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found.")
    return JSONResponse(content=task, media_type="application/a2a+json")

@app.post("/tasks/{task_id}/cancel", dependencies=[Depends(verify_bearer_token)])
async def cancel_task(task_id: str):
    state = load_state()
    if task_id not in state.get("tasks", {}):
        raise HTTPException(status_code=404, detail="Task not found.")
    state["tasks"][task_id]["status"] = "cancelled"
    save_state(state)
    return JSONResponse(content={"status": "cancelled", "task_id": task_id}, media_type="application/a2a+json")

@app.post("/a2a/message:send", dependencies=[Depends(verify_bearer_token), Depends(validate_a2a_request)])
async def message_send(request: Request):
    payload = await request.json()
    params = payload.get("params", payload)
    
    case_id = params.get("case_id", "CASE-UNKNOWN")
    recipient = params.get("recipient", "")
    action_requested = params.get("action_requested", "archive")
    evidence_text = params.get("evidence_text", "")
    signed_receipt = params.get("signed_receipt", {})

    # Scope & Receipt Validation Logic
    receipt_recipient = signed_receipt.get("recipient", "")
    receipt_status = signed_receipt.get("status", "")
    is_signature_valid = signed_receipt.get("valid", False)

    # Ensure the signed receipt strictly matches the current recipient and active status
    scope_valid = (
        is_signature_valid and 
        receipt_recipient == recipient and 
        receipt_status == "active"
    )

    action = action_requested if scope_valid else "reject"
    
    state = load_state()
    task_id = f"task-{case_id}"
    
    task_record = {
        "task_id": task_id,
        "status": "completed" if scope_valid else "rejected",
        "case_id": case_id,
        "recipient": recipient,
        "action_taken": action,
        "scope_verified": scope_valid,
        "evidence_cited": evidence_text[:150],
        "receipt": signed_receipt,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    state["tasks"][task_id] = task_record
    save_state(state)

    result = {
        "case_id": case_id,
        "action": action,
        "scope_verified": scope_valid,
        "evidence_cited": evidence_text[:150]
    }

    if "jsonrpc" in payload or "id" in payload:
        response_body = {
            "jsonrpc": "2.0",
            "result": result,
            "id": payload.get("id")
        }
    else:
        response_body = result

    return JSONResponse(content=response_body, media_type="application/a2a+json")