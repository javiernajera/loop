import os
import json
import logging
import secrets
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from urllib import request
from urllib.error import HTTPError, URLError

import boto3
from boto3.dynamodb.conditions import Key, Attr

dynamodb = boto3.resource("dynamodb")
ddb_client = boto3.client("dynamodb")

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SURVEYS_TABLE = os.environ.get("SURVEYS_TABLE", "loop_surveys")
MATCHES_TABLE = os.environ.get("MATCHES_TABLE", "loop_matches")
RELAY_TABLE = os.environ.get("RELAY_TABLE", "loop_relays")

RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
RESEND_API_URL = os.environ.get("RESEND_API_URL", "https://api.resend.com/emails")
RESEND_FROM = os.environ.get("RESEND_FROM", "Loop <hello@theloopletter.com>")
RELAY_DOMAIN = os.environ.get("RELAY_DOMAIN", "theloopletter.com")

# Tuning
MIN_SCORE = float(os.environ.get("MIN_SCORE", "0.0"))  # now float-friendly
REPEAT_WINDOW_WEEKS = int(os.environ.get("REPEAT_WINDOW_WEEKS", "12"))
GSI_WEEK_NAME = os.environ.get("GSI_WEEK_NAME", "gsi_week")

RELAY_TTL_DAYS = int(os.environ.get("RELAY_TTL_DAYS", "30"))
RELAY_RATE_LIMIT_PER_MIN = int(os.environ.get("RELAY_RATE_LIMIT_PER_MIN", "6"))
RELAY_RATE_LIMIT_BURST = int(os.environ.get("RELAY_RATE_LIMIT_BURST", "12"))
RELAY_RATE_LIMIT_WINDOW_SEC = int(os.environ.get("RELAY_RATE_LIMIT_WINDOW_SEC", "60"))

surveys_table = dynamodb.Table(SURVEYS_TABLE)
matches_table = dynamodb.Table(MATCHES_TABLE)
relay_table = dynamodb.Table(RELAY_TABLE)

# --------------------------
# Utilities
# --------------------------

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def epoch_now() -> int:
    return int(datetime.now(timezone.utc).timestamp())

def current_week_id() -> str:
    y, w, _ = datetime.now(timezone.utc).isocalendar()
    return f"{y}-W{w:02d}"

def previous_week_ids(n_weeks: int):
    out = []
    dt = datetime.now(timezone.utc)
    for i in range(1, n_weeks + 1):
        d = dt - timedelta(weeks=i)
        y, w, _ = d.isocalendar()
        out.append(f"{y}-W{w:02d}")
    return out

def match_sk(week_id: str, other_pk: str) -> str:
    return f"WEEK#{week_id}#WITH#{other_pk}"

def generate_conversation_token() -> str:
    # urlsafe token for alias and conversation id
    return secrets.token_urlsafe(16)

def build_alias(token: str, suffix: str) -> str:
    return f"c_{token}{suffix}@{RELAY_DOMAIN}"

# Dynamo AttributeValue unwrap (your surveys store AttributeValue JSON-in-string)
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

# --------------------------
# Scoring (placeholder)
# --------------------------
# Keep your existing scoring for now; swap later to genres/goal/availability.
GROUP_A = {"rebuilding", "reflective", "stabilizing"}
GROUP_B = {"exploratory", "open", "expanding"}

COMPLEMENTARY = {
    ("grounded", "reframe"), ("reframe", "grounded"),
    ("stillness", "novelty"), ("novelty", "stillness"),
    ("provocation", "reframe"), ("reframe", "provocation"),
    ("surprise", "novelty"), ("novelty", "surprise"),
}
CONFLICTS = {
    ("stillness", "provocation"), ("provocation", "stillness"),
}

def orientation_score(a, b) -> int:
    if not a or not b:
        return 0
    if a == b:
        return 3
    if (a in GROUP_A and b in GROUP_A) or (a in GROUP_B and b in GROUP_B):
        return 2
    return 0

def desired_signal_score(a_list, b_list) -> int:
    a_set = set(a_list or [])
    b_set = set(b_list or [])
    if not a_set or not b_set:
        return 0

    overlap = len(a_set & b_set)
    score = overlap * 2

    for x in a_set:
        for y in b_set:
            if (x, y) in CONFLICTS:
                score -= 2
            elif (x, y) in COMPLEMENTARY:
                score += 1
    return score

def connection_style_score(a, b) -> int:
    if not a or not b:
        return 0
    if a == b:
        return 2
    neighbors = {
        "quiet_reflection": {"thoughtful_back_and_forth", "depends"},
        "thoughtful_back_and_forth": {"quiet_reflection", "creative_exchange", "depends"},
        "creative_exchange": {"thoughtful_back_and_forth", "open_ended_wandering", "depends"},
        "practical_problem_solving": {"thoughtful_back_and_forth", "depends"},
        "open_ended_wandering": {"creative_exchange", "depends"},
        "depends": {"quiet_reflection","thoughtful_back_and_forth","creative_exchange","practical_problem_solving","open_ended_wandering"},
    }
    return 1 if b in neighbors.get(a, set()) else 0

def attention_bias_score(a, b) -> int:
    if not a or not b:
        return 0
    if a == b:
        return 1
    good = {
        ("systems", "patterns"), ("patterns", "systems"),
        ("text", "dialogue"), ("dialogue", "text"),
        ("visual", "audio"), ("audio", "visual"),
    }
    return 1 if (a, b) in good else 0

def pair_score(u, v) -> float:
    score = 0
    score += orientation_score(u.get("orientation"), v.get("orientation")) * 3
    score += desired_signal_score(u.get("desired_signals"), v.get("desired_signals")) * 4
    score += connection_style_score(u.get("connection_style"), v.get("connection_style")) * 2
    score += attention_bias_score(u.get("attention_bias"), v.get("attention_bias")) * 1
    # normalize-ish to a float band (optional). For now keep as raw int-like float
    return float(score)

def explain_match(u, v) -> str:
    overlap = list(set(u.get("desired_signals") or []) & set(v.get("desired_signals") or []))
    if overlap:
        return f"shared signal: {overlap[0]}"
    return "compatible signals"

# --------------------------
# Survey loaders
# --------------------------

def scan_all_surveys():
    resp = surveys_table.scan(
        FilterExpression=Attr("answers").exists()
    )
    items = resp.get("Items", [])
    while "LastEvaluatedKey" in resp:
        resp = surveys_table.scan(
            ExclusiveStartKey=resp["LastEvaluatedKey"],
            FilterExpression=Attr("answers").exists()
        )
        items.extend(resp.get("Items", []))
    return items

def load_latest_surveys_per_user():
    """
    Keep only latest per pk (email/user id).
    Includes only consented users and required fields.
    """
    items = scan_all_surveys()
    latest = {}

    for it in items:
        pk = it.get("pk")
        if not pk:
            continue
        cmp_key = it.get("submitted_at") or it.get("sk") or ""

        if pk not in latest or cmp_key > latest[pk]["_cmp"]:
            ans = parse_answers_string(it.get("answers", "{}"))

            if ans.get("consent") is not True:
                continue

            if not ans.get("orientation") or not ans.get("desired_signals") or not ans.get("connection_style"):
                continue

            latest[pk] = {
                "_cmp": cmp_key,
                "user_pk": pk,
                "orientation": ans.get("orientation"),
                "desired_signals": ans.get("desired_signals") or [],
                "connection_style": ans.get("connection_style"),
                "attention_bias": ans.get("attention_bias"),
            }

    return list(latest.values())

# --------------------------
# Match history helpers (week GSI)
# --------------------------

def query_matches_for_week(week_id: str, projection: str = "user_pk, matched_user_pk"):
    resp = matches_table.query(
        IndexName=GSI_WEEK_NAME,
        KeyConditionExpression=Key("gsi1pk").eq(week_id),
        ProjectionExpression=projection
    )
    items = resp.get("Items", [])
    while "LastEvaluatedKey" in resp:
        resp = matches_table.query(
            IndexName=GSI_WEEK_NAME,
            KeyConditionExpression=Key("gsi1pk").eq(week_id),
            ProjectionExpression=projection,
            ExclusiveStartKey=resp["LastEvaluatedKey"]
        )
        items.extend(resp.get("Items", []))
    return items

def build_already_matched_set(week_id: str):
    items = query_matches_for_week(week_id, projection="user_pk")
    return set(it["user_pk"] for it in items if "user_pk" in it)

def build_recent_blocklists(window_weeks: int):
    """
    Repeat avoidance: block matches from previous N completed weeks.
    """
    block = {}
    if window_weeks <= 0:
        return block

    for wid in previous_week_ids(window_weeks):
        items = query_matches_for_week(wid, projection="user_pk, matched_user_pk")
        for it in items:
            u = it.get("user_pk")
            m = it.get("matched_user_pk")
            if not u or not m:
                continue
            block.setdefault(u, set()).add(m)
    return block

# --------------------------
# Idempotent + atomic writer
# --------------------------

def transact_put_pair(u: str, v: str, week_id: str, score: float, exp_u: str, exp_v: str):
    """
    Write both directions atomically and idempotently.
    Requires loop_matches PK=(user_pk, match_sk).
    """
    now = iso_now()

    # DynamoDB expects Decimal for numbers via low-level client
    score_dec = Decimal(str(score))
    score_sort = Decimal(str(int(score * 1000)))  # integer-ish GSI sort

    item_u = {
        "user_pk": {"S": u},
        "match_sk": {"S": match_sk(week_id, v)},
        "week_id": {"S": week_id},
        "matched_user_pk": {"S": v},
        "score": {"N": str(score_dec)},
        "explain": {"S": exp_u},
        "status": {"S": "new"},
        "created_at": {"S": now},
        "gsi1pk": {"S": week_id},
        "gsi1sk": {"N": str(score_sort)},
    }

    item_v = {
        "user_pk": {"S": v},
        "match_sk": {"S": match_sk(week_id, u)},
        "week_id": {"S": week_id},
        "matched_user_pk": {"S": u},
        "score": {"N": str(score_dec)},
        "explain": {"S": exp_v},
        "status": {"S": "new"},
        "created_at": {"S": now},
        "gsi1pk": {"S": week_id},
        "gsi1sk": {"N": str(score_sort)},
    }

    ddb_client.transact_write_items(
        TransactItems=[
            {
                "Put": {
                    "TableName": MATCHES_TABLE,
                    "Item": item_u,
                    "ConditionExpression": "attribute_not_exists(match_sk)"
                }
            },
            {
                "Put": {
                    "TableName": MATCHES_TABLE,
                    "Item": item_v,
                    "ConditionExpression": "attribute_not_exists(match_sk)"
                }
            }
        ]
    )

# --------------------------
# Relay + Email
# --------------------------

def put_relay_item(alias: str, dest_email: str, counterparty_alias: str, allowed_senders, conversation_id: str):
    now_iso = iso_now()
    expires_at = epoch_now() + int(timedelta(days=RELAY_TTL_DAYS).total_seconds())
    item = {
        "alias": alias,
        "dest_email": dest_email,
        "counterparty_alias": counterparty_alias,
        "allowed_senders": list(allowed_senders),
        "conversation_id": conversation_id,
        "status": "active",
        "created_at": now_iso,
        "expires_at": expires_at,
        # Rate-limit metadata to support inbound throttling
        "rate_limit_per_min": RELAY_RATE_LIMIT_PER_MIN,
        "rate_limit_burst": RELAY_RATE_LIMIT_BURST,
        "rate_limit_window_sec": RELAY_RATE_LIMIT_WINDOW_SEC,
    }
    relay_table.put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(alias)"
    )
    return item

def get_relay_item(alias: str):
    resp = relay_table.get_item(Key={"alias": alias})
    return resp.get("Item")

def ensure_relay_pair(user_a: str, user_b: str, match_item: dict):
    """
    Idempotent relay creation for a pair.
    Uses existing conversation_id/aliases if already set.
    """
    conversation_id = match_item.get("conversation_id")
    alias_a = match_item.get("alias_a")
    alias_b = match_item.get("alias_b")

    if conversation_id and alias_a and alias_b:
        # Ensure relay records exist (can be missing due to partial failure)
        if not get_relay_item(alias_a):
            put_relay_item(alias_a, user_a, alias_b, [user_a, user_b], conversation_id)
        if not get_relay_item(alias_b):
            put_relay_item(alias_b, user_b, alias_a, [user_a, user_b], conversation_id)
        return conversation_id, alias_a, alias_b

    # No relay set yet: create new token and aliases
    conversation_id = generate_conversation_token()
    alias_a = build_alias(conversation_id, "a")
    alias_b = build_alias(conversation_id, "b")

    # Attempt to create both relay records; if either exists, re-use it
    try:
        put_relay_item(alias_a, user_a, alias_b, [user_a, user_b], conversation_id)
    except Exception as e:
        logger.warning("Relay alias_a exists or failed: %s", e)
        existing = get_relay_item(alias_a)
        if existing:
            conversation_id = existing.get("conversation_id", conversation_id)
            alias_b = existing.get("counterparty_alias", alias_b)

    try:
        put_relay_item(alias_b, user_b, alias_a, [user_a, user_b], conversation_id)
    except Exception as e:
        logger.warning("Relay alias_b exists or failed: %s", e)
        existing = get_relay_item(alias_b)
        if existing:
            conversation_id = existing.get("conversation_id", conversation_id)
            alias_a = existing.get("counterparty_alias", alias_a)

    return conversation_id, alias_a, alias_b

def update_match_with_relay(user_pk: str, other_pk: str, week_id: str, conversation_id: str, alias_a: str, alias_b: str, relay_status: str, intro_email_sent: bool, intro_email_error: str | None = None):
    update_parts = [
        "conversation_id = if_not_exists(conversation_id, :cid)",
        "alias_a = if_not_exists(alias_a, :aa)",
        "alias_b = if_not_exists(alias_b, :ab)",
        "relay_status = if_not_exists(relay_status, :rs)",
        "updated_at = :now"
    ]
    expr_vals = {
        ":cid": conversation_id,
        ":aa": alias_a,
        ":ab": alias_b,
        ":rs": relay_status,
        ":now": iso_now(),
    }

    if intro_email_sent:
        update_parts.append("intro_email_sent = :ies")
        expr_vals[":ies"] = True
    else:
        update_parts.append("intro_email_sent = if_not_exists(intro_email_sent, :ies_default)")
        expr_vals[":ies_default"] = False

    if intro_email_error:
        update_parts.append("intro_email_error = :iee")
        expr_vals[":iee"] = intro_email_error

    matches_table.update_item(
        Key={"user_pk": user_pk, "match_sk": match_sk(week_id, other_pk)},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeValues=expr_vals
    )

def send_resend_email(to_email: str, reply_to: str, subject: str, text_body: str) -> tuple[bool, str]:
    if not RESEND_API_KEY:
        return False, "Missing RESEND_API_KEY"

    payload = {
        "from": RESEND_FROM,
        "to": [to_email],
        "reply_to": reply_to,
        "subject": subject,
        "text": text_body,
    }

    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        RESEND_API_URL,
        data=data,
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=10) as resp:
            status = resp.status
            if 200 <= status < 300:
                return True, "sent"
            return False, f"Resend status {status}"
    except HTTPError as e:
        return False, f"Resend HTTPError {e.code}"
    except URLError as e:
        return False, f"Resend URLError {e.reason}"
    except Exception as e:
        return False, f"Resend error {e}"

def build_intro_email_body(user_email: str, reply_to_alias: str) -> str:
    return (
        "You’ve been matched on Loop.\n\n"
        "Reply to this email to reach your match anonymously. "
        "Your personal email stays private and messages are relayed through Loop.\n\n"
        f"Reply-To: {reply_to_alias}\n\n"
        "If you’d like to stop receiving relay messages, just let us know."
    )

def ensure_relay_and_intro(user_a: str, user_b: str, week_id: str):
    match_item = matches_table.get_item(
        Key={"user_pk": user_a, "match_sk": match_sk(week_id, user_b)}
    ).get("Item")

    if not match_item:
        return {"ok": False, "reason": "match_not_found"}

    if match_item.get("relay_status") == "active" and match_item.get("conversation_id") and match_item.get("alias_a") and match_item.get("alias_b") and match_item.get("intro_email_sent") is True:
        return {"ok": True, "status": "already_active"}

    conversation_id, alias_a, alias_b = ensure_relay_pair(user_a, user_b, match_item)

    # Update both match records with relay metadata
    update_match_with_relay(user_a, user_b, week_id, conversation_id, alias_a, alias_b, "active", False)
    update_match_with_relay(user_b, user_a, week_id, conversation_id, alias_a, alias_b, "active", False)

    # Send intro emails (only if not already sent)
    intro_sent = True
    errors = []

    if match_item.get("intro_email_sent") is not True:
        subj = "Your Loop match is here"
        ok_a, msg_a = send_resend_email(user_a, reply_to=alias_b, subject=subj, text_body=build_intro_email_body(user_a, alias_b))
        ok_b, msg_b = send_resend_email(user_b, reply_to=alias_a, subject=subj, text_body=build_intro_email_body(user_b, alias_a))
        if not ok_a or not ok_b:
            intro_sent = False
            if not ok_a:
                errors.append(f"user_a:{msg_a}")
            if not ok_b:
                errors.append(f"user_b:{msg_b}")

    if intro_sent:
        update_match_with_relay(user_a, user_b, week_id, conversation_id, alias_a, alias_b, "active", True)
        update_match_with_relay(user_b, user_a, week_id, conversation_id, alias_a, alias_b, "active", True)
    else:
        update_match_with_relay(user_a, user_b, week_id, conversation_id, alias_a, alias_b, "active", False, ";".join(errors))
        update_match_with_relay(user_b, user_a, week_id, conversation_id, alias_a, alias_b, "active", False, ";".join(errors))

    return {"ok": True, "conversation_id": conversation_id, "alias_a": alias_a, "alias_b": alias_b, "intro_sent": intro_sent}

# --------------------------
# Matching strategy (global-edge greedy; less biased)
# --------------------------

def build_edges(users):
    """
    For scale, you’ll limit to top-K per user.
    For now: full graph (OK for small N).
    """
    by_pk = {u["user_pk"]: u for u in users}
    pks = list(by_pk.keys())
    edges = []
    for i in range(len(pks)):
        for j in range(i + 1, len(pks)):
            a = by_pk[pks[i]]
            b = by_pk[pks[j]]
            s = pair_score(a, b)
            edges.append((s, a["user_pk"], b["user_pk"]))
    edges.sort(reverse=True, key=lambda x: x[0])
    return edges

def lambda_handler(event, context):
    event = event or {}
    dry_run = bool(event.get("dry_run"))
    repair_relays = bool(event.get("repair_relays"))

    week_id = current_week_id()

    users = load_latest_surveys_per_user()
    if len(users) < 2:
        return {"ok": True, "week_id": week_id, "users": len(users), "pairs": 0, "records_written": 0, "dry_run": dry_run}

    by_pk = {u["user_pk"]: u for u in users}
    already_matched = build_already_matched_set(week_id)
    recent_blocks = build_recent_blocklists(REPEAT_WINDOW_WEEKS)

    edges = build_edges(users)

    matched_now = set(already_matched)
    created = 0
    pairs = 0
    relay_results = []

    for s, u, v in edges:
        if s < MIN_SCORE:
            break
        if u in matched_now or v in matched_now:
            continue

        # repeat avoidance symmetrical
        if v in recent_blocks.get(u, set()):
            continue
        if u in recent_blocks.get(v, set()):
            continue

        exp_u = explain_match(by_pk[u], by_pk[v])
        exp_v = explain_match(by_pk[v], by_pk[u])

        # mark matched in this run first
        matched_now.add(u)
        matched_now.add(v)

        if dry_run:
            pairs += 1
            created += 2
            continue

        try:
            # atomic + idempotent
            transact_put_pair(u, v, week_id, s, exp_u, exp_v)
            pairs += 1
            created += 2

            # Relay + intro email (partial failures do not break batch)
            try:
                relay_results.append(ensure_relay_and_intro(u, v, week_id))
            except Exception as re:
                logger.exception("relay_intro_failed for %s/%s: %s", u, v, re)
        except Exception as e:
            # If transaction fails (conditional / throughput), roll back in-memory lock for this run
            matched_now.discard(u)
            matched_now.discard(v)

    # Optional: repair relays for already matched pairs in this week
    if repair_relays and not dry_run:
        try:
            items = query_matches_for_week(week_id, projection="user_pk, matched_user_pk, relay_status, conversation_id, alias_a, alias_b, intro_email_sent")
            seen_pairs = set()
            for it in items:
                u = it.get("user_pk")
                v = it.get("matched_user_pk")
                if not u or not v:
                    continue
                key = tuple(sorted([u, v]))
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                try:
                    relay_results.append(ensure_relay_and_intro(u, v, week_id))
                except Exception as re:
                    logger.exception("relay_repair_failed for %s/%s: %s", u, v, re)
        except Exception as e:
            logger.exception("repair_relays_failed: %s", e)

    return {
        "ok": True,
        "week_id": week_id,
        "users": len(users),
        "pairs": pairs,
        "records_written": 0 if dry_run else created,
        "records_computed": created,
        "already_matched_this_week": len(already_matched),
        "min_score": MIN_SCORE,
        "repeat_window_weeks": REPEAT_WINDOW_WEEKS,
        "dry_run": dry_run,
        "relay_results_count": len(relay_results)
    }
