import os
import json
import time
import base64
import hmac
import hashlib
import logging
from urllib import request, error
import boto3
from email.utils import parseaddr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ddb = boto3.resource("dynamodb")
TABLE_NAME = os.environ["RELAY_TABLE"]
table = ddb.Table(TABLE_NAME)

RESEND_API_KEY = os.environ["RESEND_API_KEY"]
WEBHOOK_SECRET = os.environ["RESEND_WEBHOOK_SECRET"]

# Tune as you like
MAX_SKEW_SECONDS = 5 * 60  # replay protection window


def _b64decode_loose(s: str) -> bytes:
    """Base64 decode with padding tolerance."""
    s = (s or "").strip()
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s + pad)


def _svix_secret_bytes(secret: str) -> bytes:
    """
    Svix secrets typically look like: whsec_<base64>
    Svix manual verification says to base64-decode the portion after 'whsec_'.
    We'll support both whsec_ and "raw base64" secrets.
    """
    secret = (secret or "").strip()
    if secret.startswith("whsec_"):
        return _b64decode_loose(secret.split("_", 1)[1])
    # If user stored raw base64
    try:
        return _b64decode_loose(secret)
    except Exception:
        # Last resort: treat as raw bytes
        return secret.encode("utf-8")


def _get_raw_body(event: dict) -> str:
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8", errors="replace")
    return body


def _lower_headers(event: dict) -> dict:
    return {str(k).lower(): v for k, v in (event.get("headers") or {}).items()}


def _timing_safe_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def verify_svix(headers: dict, raw_body: str, secret: str) -> None:
    """
    Manual Svix verification:
      signed_content = "{svix-id}.{svix-timestamp}.{raw_body}"
      signature = base64(hmac_sha256(secret_bytes, signed_content))
      Match against one of the signatures in 'svix-signature' header.

    Ref: Svix manual verification docs. :contentReference[oaicite:2]{index=2}
    """
    svix_id = headers.get("svix-id")
    svix_ts = headers.get("svix-timestamp")
    svix_sig = headers.get("svix-signature")

    if not (svix_id and svix_ts and svix_sig):
        raise ValueError("Missing svix headers")

    # Replay protection
    try:
        ts = int(svix_ts)
    except ValueError:
        raise ValueError("Invalid svix-timestamp")

    now = int(time.time())
    if abs(now - ts) > MAX_SKEW_SECONDS:
        raise ValueError("svix-timestamp outside allowed skew window")

    signed_content = f"{svix_id}.{svix_ts}.{raw_body}".encode("utf-8")
    key = _svix_secret_bytes(secret)

    expected = base64.b64encode(hmac.new(key, signed_content, hashlib.sha256).digest()).decode("utf-8")

    # svix-signature format: "v1,<sig> v1,<sig2> ..."
    # Need to match any v1 signature.
    candidates = []
    for part in svix_sig.split():
        if "," in part:
            ver, sig = part.split(",", 1)
            if ver.strip() == "v1":
                candidates.append(sig.strip())

    if not candidates:
        raise ValueError("No v1 signatures found in svix-signature")

    if not any(_timing_safe_equals(expected, cand) for cand in candidates):
        raise ValueError("Invalid svix signature")


def _normalize_email(addr: str) -> str:
    return (addr or "").strip().lower()


def _extract_email(value: str) -> str:
    # Handles "Name <email@domain>"
    _, addr = parseaddr(value or "")
    return _normalize_email(addr or value)


def resend_get_received_email(email_id: str) -> dict:
    """
    GET https://api.resend.com/emails/receiving/{id}
    Returns html/text/headers/etc. :contentReference[oaicite:3]{index=3}
    """
    url = f"https://api.resend.com/emails/receiving/{email_id}"
    req = request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Accept": "application/json",
            "User-Agent": "LoopRelay/1.0 (+https://theloopletter.com)"
        },
    )
    try:
        with request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Resend receiving GET failed: {e.code} {body}")


def resend_send_email(payload: dict) -> dict:
    """
    POST https://api.resend.com/emails :contentReference[oaicite:4]{index=4}
    """
    url = "https://api.resend.com/emails"
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        method="POST",
        data=data,
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "LoopRelay/1.0 (+https://theloopletter.com)"
        },
    )

    try:
        with request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Resend send POST failed: {e.code} {body}")


def lambda_handler(event, context):
    raw_body = _get_raw_body(event)
    headers = _lower_headers(event)

    # 1) Verify webhook signature (Svix)
    try:
        verify_svix(headers, raw_body, WEBHOOK_SECRET)
    except Exception as e:
        logger.warning("Webhook verification failed: %s", str(e))
        return {"statusCode": 400, "body": "invalid webhook"}

    # 2) Parse payload
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        return {"statusCode": 400, "body": "invalid json"}

    if payload.get("type") != "email.received":
        return {"statusCode": 200, "body": "ignored"}

    data = payload.get("data") or {}
    to_list = data.get("to") or []
    alias = _normalize_email(to_list[0] if to_list else "")
    sender = _extract_email(data.get("from") or "")
    email_id = data.get("email_id")

    if not (alias and sender and email_id):
        return {"statusCode": 400, "body": "missing fields"}

    # 3) Look up relay mapping
    resp = table.get_item(Key={"alias": alias})
    item = resp.get("Item")
    if not item or item.get("status") != "active":
        return {"statusCode": 404, "body": "alias not found"}

    allowed = set(_normalize_email(x) for x in (item.get("allowed_senders") or []))
    if allowed and sender not in allowed:
        return {"statusCode": 403, "body": "sender not allowed"}

    dest_email = item["dest_email"]
    reply_to_alias = item["counterparty_alias"]

    # 4) Fetch full email content from Resend receiving API
    subject = data.get("subject") or "(no subject)"

    # Body content fetch is blocked (403 / 1010), so forward minimal content for now.
    text = ""
    html = None

    # 5) Forward anonymously via Resend send API
    out = {
    "from": "Loop Relay <note@theloopletter.com>",
    "to": [dest_email],
    "subject": f"Re: {subject}",
    "reply_to": [reply_to_alias],
    "text": (
        f"From (via Loop Relay): {sender}\n\n"
        "Message content is temporarily unavailable while Loop finishes enabling inbound email content access.\n"
        f"(email_id: {email_id})\n"
        )
    }

    if html:
        out["html"] = f"<p><strong>From (via Loop Relay):</strong> {sender}</p><hr/>{html}"

    send_result = resend_send_email(out)

    logger.info("Forwarded: alias=%s sender=%s -> %s reply_to=%s resend=%s",
                alias, sender, dest_email, reply_to_alias, send_result.get("id") or send_result)

    return {"statusCode": 200, "body": "ok"}
