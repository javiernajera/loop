import json
import os
import time
import hashlib
import traceback
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

# ===== ENV =====
SIGNUP_TABLE = os.environ.get("SIGNUP_TABLE", "loop_users")
SURVEY_TABLE = os.environ.get("SURVEY_TABLE", "loop_surveys")

ALLOW_ORIGIN_DEFAULT = os.environ.get("ALLOW_ORIGIN_DEFAULT", "https://www.theloopletter.com")
CORS_ALLOWED_ORIGINS = os.environ.get("CORS_ALLOWED_ORIGINS", "")

# ===== AWS =====
ddb = boto3.resource("dynamodb")
signup_table = ddb.Table(SIGNUP_TABLE)
survey_table = ddb.Table(SURVEY_TABLE)

def _allowed_origins_set():
    items = [x.strip() for x in (CORS_ALLOWED_ORIGINS or "").split(",") if x.strip()]
    return set(items)

ALLOWED_ORIGINS = _allowed_origins_set()

def _get_header(event, name: str):
    h = event.get("headers") or {}
    for k, v in h.items():
        if k.lower() == name.lower():
            return v
    return ""

def _origin(event) -> str:
    return (_get_header(event, "origin") or "").strip()

def _cors_allow_origin(event) -> str:
    o = _origin(event)
    if ALLOWED_ORIGINS:
        return o if o in ALLOWED_ORIGINS else ALLOW_ORIGIN_DEFAULT
    return "*"

def _resp(event, status: int, body: dict):
    return {
        "statusCode": status,
        "headers": {
            "Access-Control-Allow-Origin": _cors_allow_origin(event),
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "OPTIONS,POST",
            "Content-Type": "application/json",
        },
        "body": json.dumps(body),
    }

def _method(event) -> str:
    return (
        event.get("requestContext", {}).get("http", {}).get("method")
        or event.get("httpMethod")
        or ""
    ).upper()

def _now_iso_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def lambda_handler(event, context):
    if _method(event) == "OPTIONS":
        return _resp(event, 200, {"ok": True})

    # Parse JSON
    try:
        raw_body = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            import base64
            raw_body = base64.b64decode(raw_body).decode("utf-8")
        data = json.loads(raw_body)
    except Exception:
        return _resp(event, 400, {"ok": False, "error": "Invalid JSON body"})

    token = (data.get("token") or "").strip()
    answers = data.get("answers")
    email_hint = (data.get("email") or "").strip().lower()

    if not token:
        return _resp(event, 400, {"ok": False, "error": "Missing token"})
    if answers is None:
        return _resp(event, 400, {"ok": False, "error": "Missing answers"})

    token_hash = _sha256(token)

    # --- Find matching signup record ---
    # Fast path if email is provided: fetch that user and compare hashes
    # Your signup record key scheme: pk=email, sk=PROFILE
    try:
        matched_email = None

        if email_hint:
            r = signup_table.get_item(Key={"pk": email_hint, "sk": "PROFILE"})
            item = r.get("Item")
            if item and item.get("survey_token_hash") == token_hash:
                matched_email = email_hint

        # If no email provided or mismatch: (optional) you’d need a GSI on survey_token_hash.
        # Without a GSI, you can't efficiently find a user by token hash alone.
        if not matched_email:
            return _resp(
                event,
                400,
                {
                    "ok": False,
                    "error": "Invalid token (or email mismatch). Please use the exact link from your email.",
                    "needs": "Include email in the request (recommended) OR add a GSI on survey_token_hash.",
                },
            )

        # --- Persist survey submission ---
        submitted_at = _now_iso_z()

        # Assumption: user_surveys table uses pk/sk as well.
        # We'll store one survey per timestamp:
        survey_item = {
            "pk": matched_email,
            "sk": f"SURVEY#{submitted_at}",
            "email": matched_email,
            "submitted_at": submitted_at,
            "answers": answers,
            "created_at_epoch": int(time.time()),
        }

        survey_table.put_item(Item=survey_item)

        # Optional: update signup status
        signup_table.update_item(
            Key={"pk": matched_email, "sk": "PROFILE"},
            UpdateExpression="SET #st=:s, updated_at=:u, survey_completed_at=:c",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":s": "survey_completed",
                ":u": submitted_at,
                ":c": submitted_at,
            },
        )

        return _resp(event, 200, {"ok": True, "email": matched_email, "submitted_at": submitted_at})

    except ClientError as e:
        err = e.response.get("Error", {})
        print("CLIENT ERROR:", err.get("Code", ""), err.get("Message", ""))
        print("TRACEBACK:\n", traceback.format_exc())
        return _resp(event, 500, {"ok": False, "error": "Server error", "code": err.get("Code", ""), "message": err.get("Message", "")})

    except Exception as e:
        print("UNHANDLED:", repr(e))
        print("TRACEBACK:\n", traceback.format_exc())
        return _resp(event, 500, {"ok": False, "error": "Unhandled error", "message": str(e)})
