import json
import os
import re
import time
import secrets
import hashlib
import traceback
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

# ========= ENV =========
# DynamoDB (table must have PK=pk (S) and SK=sk (S))
TABLE_NAME = os.environ.get("TABLE_NAME", "loop_users")

# CORS
ALLOW_ORIGIN_DEFAULT = os.environ.get("ALLOW_ORIGIN_DEFAULT", "https://www.theloopletter.com")
CORS_ALLOWED_ORIGINS = os.environ.get("CORS_ALLOWED_ORIGINS", "")

# Email / survey link
SES_FROM_EMAIL = os.environ.get("SES_FROM_EMAIL", "Welcome@theloopletter.com")
SES_REGION = os.environ.get("SES_REGION", "us-east-1")

# Use your domain here when ready, e.g. https://www.theloopletter.com/survey.html
SURVEY_BASE_URL = os.environ.get(
    "SURVEY_BASE_URL",
    "www.theloopletter.com/survey.html",
)

# If true, repeat signups refresh token + re-send email
ALLOW_RESEND = os.environ.get("ALLOW_RESEND", "false").lower()

# ========= AWS CLIENTS =========
ddb = boto3.resource("dynamodb")
table = ddb.Table(TABLE_NAME)

ses = boto3.client("ses", region_name=SES_REGION) if SES_REGION else boto3.client("ses")

# ========= VALIDATION =========
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


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
    """
    Echo request origin if it's allowlisted; otherwise fall back to default.
    If allowlist is empty, allow all (*) for early dev.
    """
    o = _origin(event)
    if ALLOWED_ORIGINS:
        return o if o in ALLOWED_ORIGINS else ALLOW_ORIGIN_DEFAULT
    return "*"


def _resp(event, status: int, body: dict):
    allow_origin = _cors_allow_origin(event)
    return {
        "statusCode": status,
        "headers": {
            "Access-Control-Allow-Origin": allow_origin,
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


def _ddb_key(email: str) -> dict:
    """
    Your user_signup table uses PK=pk and SK=sk.
    We store one record per user with sk='PROFILE'.
    """
    return {"pk": email, "sk": "PROFILE"}


def _send_survey_email(to_email: str, token: str) -> str:
    link = f"{SURVEY_BASE_URL}?token={token}&email={to_email}"
    subject = "Your Loop survey link"
    text = (
        "Thanks for signing up.\n\n"
        f"Here’s your survey link:\n{link}\n\n"
        "— The Loop"
    )

    ses.send_email(
        Source=SES_FROM_EMAIL,
        Destination={"ToAddresses": [to_email]},
        Message={
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {"Text": {"Data": text, "Charset": "UTF-8"}},
        },
    )
    return link


def lambda_handler(event, context):
    # CORS preflight
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

    email = (data.get("email") or "").strip().lower()
    source = (data.get("source") or "landing_page").strip()

    if not email or not EMAIL_RE.match(email):
        return _resp(event, 400, {"ok": False, "error": "Valid 'email' is required"})

    created_at = _now_iso_z()

    # Generate token (store only hash in DDB, send raw token in email link)
    raw_token = secrets.token_urlsafe(24)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    key = _ddb_key(email)

    item = {
        **key,  # ✅ includes pk + sk
        "email": email,
        "created_at": created_at,
        "source": source,
        "survey_token_hash": token_hash,
        "survey_token_created_at": created_at,
        "status": "pending_survey",
        "updated_at": created_at,
        "signup_count": 1,
    }

    try:
        if ALLOW_RESEND == "true":
            # Update existing user record (or create attributes if it exists)
            table.update_item(
                Key=key,
                UpdateExpression=(
                    "SET #src=:s, #st=:st, "
                    "survey_token_hash=:h, survey_token_created_at=:t, updated_at=:u "
                    "ADD signup_count :one"
                ),
                ExpressionAttributeNames={"#src": "source", "#st": "status"},
                ExpressionAttributeValues={
                    ":s": source,
                    ":st": "pending_survey",
                    ":h": token_hash,
                    ":t": created_at,
                    ":u": created_at,
                    ":one": 1,
                },
            )
        else:
            # Only create if this user doesn't already exist
            table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(pk)",
            )

        # Send email (if SES errors, it will be logged + returned)
        link = _send_survey_email(email, raw_token)

        return _resp(event, 200, {"ok": True, "email": email, "status": "pending_survey", "survey_link": link})

    except ClientError as e:
        err = e.response.get("Error", {})
        code = err.get("Code", "")
        msg = err.get("Message", "")
        print("CLIENT ERROR:", code, msg)
        print("TRACEBACK:\n", traceback.format_exc())

        if code == "ConditionalCheckFailedException":
            return _resp(event, 200, {"ok": True, "email": email, "status": "already_signed_up"})

        return _resp(event, 500, {"ok": False, "error": "Signup failed", "code": code, "message": msg})

    except Exception as e:
        print("UNHANDLED ERROR:", repr(e))
        print("TRACEBACK:\n", traceback.format_exc())
        return _resp(event, 500, {"ok": False, "error": "Unhandled error", "message": str(e)})
