import json
import os
import re
import secrets
import hashlib
import traceback
import urllib.request
import urllib.error
import base64
from urllib.parse import urlencode
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

# ========= ENV =========
# DynamoDB table must have PK=pk (S) and SK=sk (S)
TABLE_NAME = os.environ.get("TABLE_NAME", "loop_users")

# CORS
ALLOW_ORIGIN_DEFAULT = os.environ.get("ALLOW_ORIGIN_DEFAULT", "https://www.theloopletter.com")
CORS_ALLOWED_ORIGINS = os.environ.get("CORS_ALLOWED_ORIGINS", "")

# Resend / Secrets Manager
RESEND_SECRET_ID = os.environ.get(
    "RESEND_SECRET_ID",
    "arn:aws:secretsmanager:us-east-1:321168214871:secret:RESEND-5FS0q3",
)
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "Loop <hello@theloopletter.com>")
RESEND_REPLY_TO = os.environ.get("RESEND_REPLY_TO")  # optional (email string)

# Survey link base URL (must include https://)
SURVEY_BASE_URL = os.environ.get("SURVEY_BASE_URL", "https://www.theloopletter.com/survey.html")

# If true, repeat signups refresh token + re-send email
ALLOW_RESEND = os.environ.get("ALLOW_RESEND", "false").lower()

# ========= AWS CLIENTS =========
ddb = boto3.resource("dynamodb")
table = ddb.Table(TABLE_NAME)
secrets_client = boto3.client("secretsmanager")

# ========= VALIDATION =========
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_cached_resend_key = None


def _now_iso_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _get_resend_api_key() -> str:
    """Fetch Resend API key from Secrets Manager and cache it for warm invocations."""
    global _cached_resend_key
    if _cached_resend_key:
        return _cached_resend_key

    if not RESEND_SECRET_ID:
        raise RuntimeError("RESEND_SECRET_ID is not set")

    resp = secrets_client.get_secret_value(SecretId=RESEND_SECRET_ID)

    if resp.get("SecretString"):
        s = resp["SecretString"]
    else:
        s = base64.b64decode(resp["SecretBinary"]).decode("utf-8")

    # Secret can be raw key OR JSON like {"RESEND_API_KEY":"re_..."}
    try:
        obj = json.loads(s)
        key = obj.get("RESEND_API_KEY") or obj.get("api_key") or obj.get("key")
    except Exception:
        key = s.strip()

    if not key:
        raise RuntimeError("Resend API key not found in secret")

    _cached_resend_key = key.strip()
    return _cached_resend_key


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


def _ddb_key(email: str) -> dict:
    """
    Table uses PK=pk and SK=sk.
    We store one record per user with sk='PROFILE'.
    """
    return {"pk": email, "sk": "PROFILE"}


def _urlopen_json(req: urllib.request.Request, timeout: int = 15) -> dict:
    """
    Wrapper that prints URL + body on HTTPError for easier debugging.
    """
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace") or "{}"
            try:
                return json.loads(raw)
            except Exception:
                return {"raw": raw}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        print("HTTPError URL:", getattr(req, "full_url", None) or getattr(e, "url", None))
        print("HTTPError Status:", e.code, e.reason)
        print("HTTPError Body:", err_body[:4000])
        raise
    except Exception as e:
        print("URLOPEN ERROR:", repr(e))
        raise


def _send_survey_email(to_email: str, token: str) -> str:
    qs = urlencode({"token": token, "email": to_email})
    link = f"{SURVEY_BASE_URL}?{qs}"

    subject = "Your Loop survey link"
    text = (
        "Thanks for signing up.\n\n"
        f"Here’s your survey link:\n{link}\n\n"
        "If anything looks off, just reply to this email.\n\n"
        "— Loop"
    )

    api_key = _get_resend_api_key()

    payload = {
        "from": RESEND_FROM_EMAIL,
        "to": [to_email],
        "subject": subject,
        "text": text,
    }
    if RESEND_REPLY_TO:
        payload["reply_to"] = [RESEND_REPLY_TO] if isinstance(RESEND_REPLY_TO, str) else RESEND_REPLY_TO

    body = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            # Important for avoiding Cloudflare/WAF false positives in some environments
            "User-Agent": "LoopSignup/1.0 (+https://www.theloopletter.com)",
        },
        method="POST",
    )

    _urlopen_json(req, timeout=15)
    return link


def lambda_handler(event, context):
    # CORS preflight
    if _method(event) == "OPTIONS":
        return _resp(event, 200, {"ok": True})

    # Parse JSON
    try:
        raw_body = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            raw_body = base64.b64decode(raw_body).decode("utf-8", errors="replace")
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
        **key,
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
        # Write user first; if email send fails we mark status=email_failed for safe retry.
        if ALLOW_RESEND == "true":
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
            table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(pk)",
            )

        # Send email via Resend
        try:
            link = _send_survey_email(email, raw_token)
        except Exception:
            # Mark email failure but keep record so we can retry without duplicating users
            try:
                table.update_item(
                    Key=key,
                    UpdateExpression="SET #st=:st, updated_at=:u",
                    ExpressionAttributeNames={"#st": "status"},
                    ExpressionAttributeValues={":st": "email_failed", ":u": _now_iso_z()},
                )
            except Exception as inner:
                print("FAILED to update email_failed status:", repr(inner))
            raise

        return _resp(
            event,
            200,
            {"ok": True, "email": email, "status": "pending_survey", "survey_link": link},
        )

    except ClientError as e:
        err = e.response.get("Error", {})
        code = err.get("Code", "")
        msg = err.get("Message", "")

        # Expected: email already signed up (when ALLOW_RESEND=false)
        if code == "ConditionalCheckFailedException":
            return _resp(event, 200, {"ok": True, "email": email, "status": "already_signed_up"})

        print("CLIENT ERROR:", code, msg)
        print("TRACEBACK:\n", traceback.format_exc())
        return _resp(event, 500, {"ok": False, "error": "Signup failed", "code": code, "message": msg})

    except Exception as e:
        print("UNHANDLED ERROR:", repr(e))
        print("TRACEBACK:\n", traceback.format_exc())
        return _resp(event, 500, {"ok": False, "error": "Unhandled error", "message": str(e)})
