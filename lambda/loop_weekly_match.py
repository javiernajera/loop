import os
import json
import hashlib
import logging
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import urllib.request
import base64

import boto3
from boto3.dynamodb.conditions import Key


# ============================================================
# Loop weekly intro sender (Case 2 relay model)
# - Reads weekly matches (loop_matches) from GSI gsi_week
# - For each matched pair, creates a relay record in loop_relays (idempotent)
# - Atomically marks BOTH directional match records as emailed (idempotent)
# - Sends an intro email to ONE user per invocation attempt; the other
#   direction will be skipped due to the transaction condition.
# ============================================================

# -----------------------
# Env / clients
# -----------------------
REGION = os.environ.get("AWS_REGION", "us-east-1")

MATCHES_TABLE = os.environ.get("MATCHES_TABLE", "loop_matches")
SURVEYS_TABLE = os.environ.get("SURVEYS_TABLE", "loop_surveys")
RELAYS_TABLE = os.environ.get("RELAYS_TABLE", "loop_relays")

GSI_WEEK_NAME = os.environ.get("GSI_WEEK_NAME", "gsi_week")

# Email settings
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
RESEND_SECRET_ID = os.environ.get("RESEND_SECRET_ID")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "Loop <hello@theloopletter.com>")
REPLY_DOMAIN = os.environ.get("REPLY_DOMAIN", "theloopletter.com")
INTRO_SUBJECT = os.environ.get("INTRO_SUBJECT", "Your Loop intro for this week")

# Resend rate-limit handling
RESEND_RATE_LIMIT_PER_SEC = float(os.environ.get("RESEND_RATE_LIMIT_PER_SEC", "2"))
RESEND_RETRY_MAX = int(os.environ.get("RESEND_RETRY_MAX", "3"))
RESEND_RETRY_BASE_DELAY = float(os.environ.get("RESEND_RETRY_BASE_DELAY", "0.5"))

# Optional: enforce "send at most N per invocation"
MAX_SEND = int(os.environ.get("MAX_SEND", "200"))

dynamodb = boto3.resource("dynamodb", region_name=REGION)
ddb_client = boto3.client("dynamodb", region_name=REGION)
secrets_client = boto3.client("secretsmanager", region_name=REGION)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

matches_table = dynamodb.Table(MATCHES_TABLE)
surveys_table = dynamodb.Table(SURVEYS_TABLE)
relays_table = dynamodb.Table(RELAYS_TABLE)

_cached_resend_key = None


# -----------------------
# Time helpers
# -----------------------
def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def current_week_id() -> str:
    y, w, _ = datetime.now(timezone.utc).isocalendar()
    return f"{y}-W{w:02d}"


# -----------------------
# Relay helpers (Case 2)
# -----------------------
def deterministic_alias(week_id: str, a: str, b: str) -> str:
    """
    Stable per-week per-pair alias. If you want alias stable across weeks, remove week_id from hash.
    """
    lo, hi = sorted([a.strip().lower(), b.strip().lower()])
    seed = f"{week_id}|{lo}|{hi}"
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]
    return f"c_{h}@{REPLY_DOMAIN}"

def canonical_pair(a: str, b: str):
    lo, hi = sorted([a.strip().lower(), b.strip().lower()])
    return lo, hi

def ensure_relay_exists(alias: str, week_id: str, user_a: str, user_b: str) -> bool:
    """
    Create relay record if missing. Idempotent via conditional write.
    Returns True if created, False if already existed.
    """
    lo, hi = canonical_pair(user_a, user_b)
    try:
        relays_table.put_item(
            Item={
                "alias": alias,
                "week_id": week_id,
                "user_a": lo,
                "user_b": hi,
                "created_at": iso_now(),
                "status": "active",
            },
            ConditionExpression="attribute_not_exists(alias)",
        )
        return True
    except Exception:
        return False


# -----------------------
# Survey parsing helpers
# -----------------------
def unwrap_attr(av):
    if not isinstance(av, dict) or len(av) != 1:
        return av
    t, v = next(iter(av.items()))
    if t == "S": return v
    if t == "N": return float(v) if "." in v else int(v)
    if t == "BOOL": return bool(v)
    if t == "NULL": return None
    if t == "L": return [unwrap_attr(x) for x in v]
    if t == "M": return {k: unwrap_attr(val) for k, val in v.items()}
    return v

def parse_answers_string(s: str) -> dict:
    try:
        raw = json.loads(s)
        return {k: unwrap_attr(v) for k, v in raw.items()}
    except Exception:
        return {}

def safe_join(xs: List[str], max_items: int = 2) -> str:
    xs = [x for x in xs if x]
    return ", ".join(xs[:max_items])

def build_profile_blurb(answers: Dict[str, Any]) -> str:
    """
    Minimal, non-creepy summary. Works with your current (old) fields:
      - orientation
      - desired_signals
      - connection_style
      - attention_bias
    Swap later to new survey fields when ready.
    """
    orientation = answers.get("orientation")
    desired = answers.get("desired_signals") or []
    conn = answers.get("connection_style")
    attn = answers.get("attention_bias")

    lines = []
    if orientation:
        lines.append(f"- Phase: {orientation.replace('_',' ')}")
    if desired:
        lines.append(f"- Signals: {safe_join(desired, 2)}")
    if conn:
        lines.append(f"- Collab style: {conn.replace('_',' ')}")
    if attn:
        lines.append(f"- Pulls attention first: {attn}")
    if not lines:
        lines.append("- (No extra details provided)")
    return "\n".join(lines)

def load_latest_survey_answers(user_pk: str) -> Optional[Dict[str, Any]]:
    resp = surveys_table.get_item(Key={"pk": user_pk})
    it = resp.get("Item")
    if not it:
        return None
    return parse_answers_string(it.get("answers", "{}"))



# -----------------------
# Match querying (weekly)
# -----------------------
def query_matches_for_week_all(week_id: str) -> List[Dict[str, Any]]:
    """
    Pull all match records for a week via the week GSI.
    """
    resp = matches_table.query(
        IndexName=GSI_WEEK_NAME,
        KeyConditionExpression=Key("gsi1pk").eq(week_id),
    )
    items = resp.get("Items", [])
    while "LastEvaluatedKey" in resp:
        resp = matches_table.query(
            IndexName=GSI_WEEK_NAME,
            KeyConditionExpression=Key("gsi1pk").eq(week_id),
            ExclusiveStartKey=resp["LastEvaluatedKey"],
        )
        items.extend(resp.get("Items", []))
    return items


# -----------------------
# Idempotent gating (atomic)
# -----------------------
def transact_mark_emailed(user_a: str, user_b: str, week_id: str, alias: str):
    """
    Atomic: marks BOTH directional match records as emailed, stores relay_alias.
    Only succeeds if BOTH have not set intro_email_sent=true.
    This is the idempotency gate (safe to rerun).
    """
    sk_a = f"WEEK#{week_id}#WITH#{user_b}"
    sk_b = f"WEEK#{week_id}#WITH#{user_a}"
    now = iso_now()

    ddb_client.transact_write_items(
        TransactItems=[
            {
                "Update": {
                    "TableName": MATCHES_TABLE,
                    "Key": {"user_pk": {"S": user_a}, "match_sk": {"S": sk_a}},
                    "UpdateExpression": "SET intro_email_sent=:true, emailed_at=:t, relay_alias=:ra",
                    "ConditionExpression": "attribute_not_exists(intro_email_sent) OR intro_email_sent = :false",
                    "ExpressionAttributeValues": {
                        ":false": {"BOOL": False},
                        ":true": {"BOOL": True},
                        ":t": {"S": now},
                        ":ra": {"S": alias},
                    },
                }
            },
            {
                "Update": {
                    "TableName": MATCHES_TABLE,
                    "Key": {"user_pk": {"S": user_b}, "match_sk": {"S": sk_b}},
                    "UpdateExpression": "SET intro_email_sent=:true, emailed_at=:t, relay_alias=:ra",
                    "ConditionExpression": "attribute_not_exists(intro_email_sent) OR intro_email_sent = :false",
                    "ExpressionAttributeValues": {
                        ":false": {"BOOL": False},
                        ":true": {"BOOL": True},
                        ":t": {"S": now},
                        ":ra": {"S": alias},
                    },
                }
            },
        ]
    )


# -----------------------
# Email sending (Resend)
# -----------------------
import urllib.error

def _get_resend_api_key() -> str:
    """Fetch Resend API key from Secrets Manager if configured, else env var."""
    global _cached_resend_key
    if _cached_resend_key:
        return _cached_resend_key

    if RESEND_SECRET_ID:
        resp = secrets_client.get_secret_value(SecretId=RESEND_SECRET_ID)
        if resp.get("SecretString"):
            s = resp["SecretString"]
        else:
            s = base64.b64decode(resp["SecretBinary"]).decode("utf-8")

        try:
            obj = json.loads(s)
            key = obj.get("RESEND_API_KEY") or obj.get("api_key") or obj.get("key")
        except Exception:
            key = s.strip()
    else:
        key = RESEND_API_KEY

    if not key:
        raise RuntimeError("RESEND_API_KEY is not set and RESEND_SECRET_ID is empty")

    _cached_resend_key = key.strip()
    return _cached_resend_key

def resend_send_email(to_email: str, reply_to: str, subject: str, text: str) -> Dict[str, Any]:
    url = "https://api.resend.com/emails"
    api_key = _get_resend_api_key()
    payload = {
        "from": FROM_EMAIL,
        "to": [to_email],
        "reply_to": reply_to,
        "subject": subject,
        "text": text,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "LoopWeeklyMatch/1.0 (+https://www.theloopletter.com)",
        },
        method="POST",
    )

    attempt = 0
    while True:
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body) if body else {"ok": True}
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            if e.code == 429 and attempt < RESEND_RETRY_MAX:
                delay = RESEND_RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning("RESEND 429 rate limit, retrying in %.2fs", delay)
                time.sleep(delay)
                attempt += 1
                continue
            logger.error("RESEND HTTPError %s: %s", e.code, err_body)
            raise
        except Exception as e:
            logger.exception("RESEND Exception: %s", repr(e))
            raise

def build_intro_email(to_user: str, other_user: str, other_answers: Dict[str, Any], alias: str) -> str:
    other_name = other_answers.get("firstName") or "your match"
    blurb = build_profile_blurb(other_answers)
    return f"""Loop intro

This week, we’re introducing you to {other_name}.

Reply to this email to reach them — your reply will go through this relay:
{alias}

A few notes about them:
{blurb}

Tips:
- Send a short hello + what you’re making lately
- Suggest one time window to connect

— Loop
"""


# -----------------------
# Main handler
# -----------------------
def lambda_handler(event, context):
    """
    event options:
      - {"week_id": "2026-W05"}  (default current)
      - {"dry_run": true}
      - {"max_send": 50}
    """
    event = event or {}
    dry_run = bool(event.get("dry_run"))
    week_id = event.get("week_id") or current_week_id()
    max_send = int(event.get("max_send") or MAX_SEND)

    all_items = query_matches_for_week_all(week_id)
    new_items = [it for it in all_items if it.get("intro_email_sent") is not True]

    sent = 0
    attempted = 0
    skipped = 0
    errors = 0
    relays_created = 0

    last_send_ts = 0.0

    for it in new_items:
        if sent >= max_send:
            break

        user_a = it.get("user_pk")
        user_b = it.get("matched_user_pk")
        if not user_a or not user_b:
            skipped += 1
            continue

        attempted += 1
        alias = deterministic_alias(week_id, user_a, user_b)

        # Case 2 requirement: create/ensure relay mapping exists for this pair
        created = ensure_relay_exists(alias, week_id, user_a, user_b)
        if created:
            relays_created += 1

        if dry_run:
            # In dry-run we don't mark emailed or send
            sent += 1
            continue

        try:
            # Idempotency gate: only one invocation (and one direction item) will win
            transact_mark_emailed(user_a, user_b, week_id, alias)

            # Now send email to user_a about user_b
            other_answers = load_latest_survey_answers(user_b) or {}
            body = build_intro_email(user_a, user_b, other_answers, alias)

            resend_send_email(
                to_email=user_a,
                reply_to=alias,
                subject=INTRO_SUBJECT,
                text=body,
            )

            # pace outbound sends to respect Resend limits
            min_interval = 1.0 / max(RESEND_RATE_LIMIT_PER_SEC, 0.1)
            now_ts = time.time()
            elapsed = now_ts - last_send_ts
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            last_send_ts = time.time()

            sent += 1

        except Exception:
            errors += 1
            logger.exception("weekly_intro_failed: user_a=%s user_b=%s alias=%s", user_a, user_b, alias)

    return {
        "ok": True,
        "week_id": week_id,
        "dry_run": dry_run,
        "attempted": attempted,
        "sent": sent,
        "skipped": skipped,
        "errors": errors,
        "relays_created": relays_created,
        "total_week_records": len(all_items),
        "new_week_records": len(new_items),
    }
