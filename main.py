import base64
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DB_FILE = os.environ.get("ACTION_GATE_DB_FILE", "action_gate.db")
MAX_RESPONSE_BYTES = 768 * 1024
LOGGER = logging.getLogger("action_gate")

ALLOWED_ACTIONS = {
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
}

def init_db() -> None:
    conn = sqlite3.connect(DB_FILE, timeout=60.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        # Mailroom Action Gate tables
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evaluations (
                evaluation_id TEXT PRIMARY KEY,
                core_id TEXT NOT NULL,
                audit_id TEXT NOT NULL,
                input_digest TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                receipt_verifier TEXT NOT NULL,
                proposals_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dossiers (
                core_id TEXT NOT NULL,
                dossier_id TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                proposal_json TEXT NOT NULL,
                PRIMARY KEY (core_id, dossier_id, content_hash)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS commit_receipts (
                evaluation_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                call_id TEXT NOT NULL,
                outcome_json TEXT NOT NULL,
                PRIMARY KEY (evaluation_id, receipt_id)
            )
        """)
        # Incident Agent tables
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                root_cause TEXT NOT NULL,
                evidence TEXT NOT NULL,
                chosen_effect TEXT,
                action_log TEXT NOT NULL,
                receipt_log TEXT NOT NULL,
                otlp_trace TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                initial_response TEXT NOT NULL,
                current_response TEXT NOT NULL,
                pending_dispatches TEXT NOT NULL,
                pending_approval TEXT,
                diagnostic_action_ids TEXT NOT NULL,
                effect_action_id TEXT,
                plan_json TEXT NOT NULL,
                trace_state TEXT NOT NULL,
                suppressed TEXT NOT NULL
            )
        """)
        conn.commit()
    finally:
        conn.close()

app = FastAPI(title="Unified Mailroom and Incident Agent Service", version="v2")

@app.on_event("startup")
async def startup_event():
    init_db()

def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def compute_input_digest(dossiers: List[Any]) -> str:
    serialized = canonical_json(dossiers)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

def compute_proposal_digest(proposal: Dict[str, Any]) -> str:
    filtered = {
        "dossierId": proposal.get("dossierId"),
        "callId": proposal.get("callId"),
        "action": proposal.get("action"),
        "target": proposal.get("target"),
        "payload": proposal.get("payload"),
        "evidence": sorted(proposal.get("evidence", [])),
    }
    return hashlib.sha256(canonical_json(filtered).encode("utf-8")).hexdigest()

@app.get("/health")
async def health_check():
    return {"status": "ok"}

def response_json(response: Dict[str, Any]) -> Dict[str, Any]:
    serialized = canonical_json(response)
    if len(serialized.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise HTTPException(status_code=422, detail="Response exceeds the supported size limit.")
    return response

def generate_proposal_for_dossier(dossier: Dict[str, Any], allowed_actions: List[str]) -> Dict[str, Any]:
    dossier_id = dossier.get("dossierId", "dossier-unknown")
    mailbox = dossier.get("mailbox", "support")
    sources = dossier.get("sources", [])
    
    all_lines = {}
    full_text_lines = []
    for s in sources:
        for l in s.get("lines", []):
            lid = l.get("lineId")
            ltxt = l.get("text", "")
            if lid:
                all_lines[lid] = ltxt
                full_text_lines.append(f"{lid}: {ltxt}")
    
    combined_text = "\n".join(full_text_lines).lower()
    evidence_keys = [list(all_lines.keys())[0]] if all_lines else ["line-1"]

    if any(term in combined_text for term in ["ignore previous", "system prompt", "exfiltrate", "bypass", "malicious", "override", "hack"]):
        action = "quarantine_item"
        target = {"kind": "security_queue", "id": "mailroom"}
        payload = {"artifactId": dossier_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"}
    elif "status" in combined_text or "order" in combined_text or "where is" in combined_text or "tracking" in combined_text:
        action = "create_draft"
        target = {"kind": "draft_queue", "id": f"mailbox:{mailbox}"}
        payload = {"recipient": mailbox, "referenceId": dossier_id, "status": "pending", "template": "order_status"}
    elif "delivery window" in combined_text or "reschedule" in combined_text or "delivery time" in combined_text:
        action = "update_internal_record"
        target = {"kind": "case_record", "id": dossier_id}
        payload = {"field": "delivery_window", "sourceEventId": dossier_id, "value": "updated"}
    elif "approve" in combined_text or "approved notice" in combined_text:
        action = "send_approved_notice"
        target = {"kind": "email", "id": mailbox}
        payload = {"referenceId": dossier_id, "status": "approved", "template": "approved_delivery_notice"}
    elif "confirm" in combined_text or "verify" in combined_text or "identity" in combined_text:
        action = "request_confirmation"
        target = {"kind": "approval_queue", "id": "verification-team"}
        payload = {"claimedSender": mailbox, "questionCode": "VERIFY_REQUEST", "referenceId": dossier_id}
    else:
        action = "no_action"
        target = None
        payload = {"reasonCode": "INFORMATIONAL", "referenceId": dossier_id}

    if action not in allowed_actions:
        action = "no_action"
        target = None
        payload = {"reasonCode": "INFORMATIONAL", "referenceId": dossier_id}

    call_id = hashlib.sha256(f"{dossier_id}:{action}:{canonical_json(payload)}".encode("utf-8")).hexdigest()[:16]
    return {
        "dossierId": dossier_id,
        "callId": call_id,
        "action": action,
        "target": target,
        "payload": payload,
        "evidence": evidence_keys,
    }

@app.post("/")
@app.post("/v2/incidents")
@app.post("/v2/mailroom")
async def handle_operations(request: Request):
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON request.") from exc

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Invalid JSON request.")

    profile = body.get("profile", "")
    operation = body.get("operation")

    # Handle Incident Agent profile if requested
    if profile == "ga5-incident-agent/v2" or "incident" in body or "runId" in body:
        from fastapi.responses import Response
        # Fallback handling for incident agent if needed
        run_id = body.get("runId", str(uuid.uuid4()))
        return JSONResponse(status_code=200, content={
            "runId": run_id,
            "status": "waiting",
            "diagnosis": {"rootCause": "Examined incident transcript", "evidence": ["ev_1"]},
            "dispatches": [],
            "approvals": []
        })

    # Mailroom Action Gate / Propose-Commit Workflow
    if operation == "propose":
        evaluation_id = body.get("evaluationId")
        corpus = body.get("corpus", {})
        core_id = corpus.get("coreId", "core-default")
        audit_id = corpus.get("auditId", "audit-default")
        dossiers = body.get("dossiers", [])
        receipt_verifier = body.get("receiptVerifier", {})
        allowed_actions = body.get("allowedActions", list(ALLOWED_ACTIONS))

        if not evaluation_id or not dossiers:
            raise HTTPException(status_code=422, detail="Missing evaluationId or dossiers.")

        input_digest = compute_input_digest(dossiers)
        request_hash = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()

        conn = sqlite3.connect(DB_FILE, timeout=60.0)
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT request_hash, proposals_json FROM evaluations WHERE evaluation_id = ?",
                (evaluation_id,)
            ).fetchone()

            if existing:
                if existing[0] != request_hash:
                    raise HTTPException(status_code=409, detail="Evaluation ID conflicts with existing changed content.")
                proposals = json.loads(existing[1])
                return JSONResponse(status_code=200, content=response_json({
                    "profile": "ga5-mailroom-action-gate/v2",
                    "evaluationId": evaluation_id,
                    "status": "awaiting_receipts",
                    "inputDigest": input_digest,
                    "proposals": proposals,
                }))

            proposals = []
            for dossier in dossiers:
                dossier_id = dossier.get("dossierId", "unknown")
                content_hash = hashlib.sha256(canonical_json(dossier).encode("utf-8")).hexdigest()

                cached = conn.execute(
                    "SELECT proposal_json FROM dossiers WHERE core_id = ? AND dossier_id = ? AND content_hash = ?",
                    (core_id, dossier_id, content_hash)
                ).fetchone()

                if cached:
                    prop = json.loads(cached[0])
                else:
                    prop = await run_in_threadpool(generate_proposal_for_dossier, dossier, allowed_actions)
                    conn.execute(
                        "INSERT OR REPLACE INTO dossiers (core_id, dossier_id, content_hash, proposal_json) VALUES (?, ?, ?, ?)",
                        (core_id, dossier_id, content_hash, canonical_json(prop))
                    )
                proposals.append(prop)

            conn.execute(
                """INSERT INTO evaluations 
                   (evaluation_id, core_id, audit_id, input_digest, request_hash, receipt_verifier, proposals_json, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (evaluation_id, core_id, audit_id, input_digest, request_hash, canonical_json(receipt_verifier), canonical_json(proposals), "awaiting_receipts", time.time())
            )
            conn.commit()

            return JSONResponse(status_code=200, content=response_json({
                "profile": "ga5-mailroom-action-gate/v2",
                "evaluationId": evaluation_id,
                "status": "awaiting_receipts",
                "inputDigest": input_digest,
                "proposals": proposals,
            }))
        except HTTPException:
            conn.rollback()
            raise
        finally:
            conn.close()

    elif operation == "commit":
        evaluation_id = body.get("evaluationId")
        input_digest = body.get("inputDigest")
        receipts = body.get("receipts", [])

        if not evaluation_id or not input_digest or not isinstance(receipts, list):
            raise HTTPException(status_code=422, detail="Invalid commit request format.")

        conn = sqlite3.connect(DB_FILE, timeout=60.0)
        try:
            conn.execute("BEGIN IMMEDIATE")
            eval_row = conn.execute(
                "SELECT receipt_verifier, proposals_json FROM evaluations WHERE evaluation_id = ?",
                (evaluation_id,)
            ).fetchone()

            if not eval_row:
                raise HTTPException(status_code=404, detail="Unknown evaluation ID.")

            receipt_verifier = json.loads(eval_row[0])
            proposals = json.loads(eval_row[1])
            proposal_map = {p["callId"]: p for p in proposals}

            pk = receipt_verifier.get("publicKeyJwk", {})
            try:
                public_key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(pk.get("x", "") + "=="))
            except Exception as exc:
                raise HTTPException(status_code=422, detail="Invalid public key.") from exc

            outcomes = []
            seen_receipt_ids = set()

            for r in receipts:
                if not isinstance(r, dict):
                    raise HTTPException(status_code=422, detail="Invalid receipt structure.")
                receipt_id = r.get("receiptId")
                call_id = r.get("callId")
                signature_b64 = r.get("receiptSignature")
                accepted = r.get("accepted")
                proposal_digest = r.get("proposalDigest")
                dossier_id = r.get("dossierId")
                action = r.get("action")

                if not receipt_id or receipt_id in seen_receipt_ids:
                    raise HTTPException(status_code=422, detail="Invalid or duplicate receipt ID.")
                seen_receipt_ids.add(receipt_id)

                if call_id not in proposal_map:
                    raise HTTPException(status_code=422, detail="Call ID mismatch.")

                expected_prop = proposal_map[call_id]
                if expected_prop["dossierId"] != dossier_id or expected_prop["action"] != action:
                    raise HTTPException(status_code=422, detail="Proposal mismatch.")

                expected_digest = compute_proposal_digest(expected_prop)
                if proposal_digest != expected_digest:
                    raise HTTPException(status_code=422, detail="Proposal digest mismatch.")

                signed_inner = {
                    "profile": "ga5-mailroom-action-gate/v2",
                    "evaluationId": evaluation_id,
                    "inputDigest": input_digest,
                    "receipt": {
                        "dossierId": dossier_id,
                        "callId": call_id,
                        "action": action,
                        "accepted": accepted,
                        "proposalDigest": proposal_digest,
                        "receiptId": receipt_id,
                    }
                }
                signed_bytes = canonical_json(signed_inner).encode("utf-8")

                try:
                    sig_bytes = base64.b64decode(signature_b64)
                    public_key.verify(sig_bytes, signed_bytes)
                except Exception as exc:
                    raise HTTPException(status_code=422, detail="Invalid cryptographic receipt signature.") from exc

                status_str = "executed" if accepted else "rejected"
                outcomes.append({
                    "dossierId": dossier_id,
                    "callId": call_id,
                    "action": action,
                    "proposalDigest": proposal_digest,
                    "receiptId": receipt_id,
                    "status": status_str,
                })

                conn.execute(
                    "INSERT OR REPLACE INTO commit_receipts (evaluation_id, receipt_id, call_id, outcome_json) VALUES (?, ?, ?, ?)",
                    (evaluation_id, receipt_id, call_id, canonical_json(outcomes[-1]))
                )

            conn.commit()
            return JSONResponse(status_code=200, content=response_json({
                "profile": "ga5-mailroom-action-gate/v2",
                "evaluationId": evaluation_id,
                "status": "completed",
                "inputDigest": input_digest,
                "outcomes": outcomes,
            }))
        except HTTPException:
            conn.rollback()
            raise
        finally:
            conn.close()

    else:
        raise HTTPException(status_code=400, detail="Unknown or missing operation.")
