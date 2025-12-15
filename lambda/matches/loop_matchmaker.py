import os
import json
from datetime import datetime, timezone, timedelta

import boto3
from boto3.dynamodb.conditions import Key, Attr

dynamodb = boto3.resource("dynamodb")

SURVEYS_TABLE = os.environ.get("SURVEYS_TABLE", "loop_surveys")
MATCHES_TABLE = os.environ.get("MATCHES_TABLE", "loop_matches")

# Tune via env vars
MIN_SCORE = int(os.environ.get("MIN_SCORE", "0"))
REPEAT_WINDOW_WEEKS = int(os.environ.get("REPEAT_WINDOW_WEEKS", "4"))  # previous weeks only (excludes current)
GSI_WEEK_NAME = os.environ.get("GSI_WEEK_NAME", "gsi_week")

surveys_table = dynamodb.Table(SURVEYS_TABLE)
matches_table = dynamodb.Table(MATCHES_TABLE)

# --- Compatibility config ---
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

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def current_week_id() -> str:
    y, w, _ = datetime.now(timezone.utc).isocalendar()
    return f"{y}-W{w:02d}"

def previous_week_ids(n_weeks: int):
    """
    Returns the previous N *completed* ISO week ids (excludes current week).
    Example: if current week is W51 and n_weeks=2 -> ["2025-W50","2025-W49"]
    """
    out = []
    dt = datetime.now(timezone.utc)
    for i in range(1, n_weeks + 1):
        d = dt - timedelta(weeks=i)
        y, w, _ = d.isocalendar()
        out.append(f"{y}-W{w:02d}")
    return out

# --- Parse your stored answers (string containing Dynamo AttributeValue JSON) ---
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

# --- Scoring ---
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

def pair_score(u, v) -> int:
    score = 0
    score += orientation_score(u.get("orientation"), v.get("orientation")) * 3
    score += desired_signal_score(u.get("desired_signals"), v.get("desired_signals")) * 4
    score += connection_style_score(u.get("connection_style"), v.get("connection_style")) * 2
    score += attention_bias_score(u.get("attention_bias"), v.get("attention_bias")) * 1
    return score

def explain_match(u, v) -> str:
    overlap = list(set(u.get("desired_signals") or []) & set(v.get("desired_signals") or []))
    if overlap:
        return f"nearby phases, shared signal: {overlap[0]}"
    return "nearby phases, compatible signals"

# --- Dynamo loaders ---
def scan_all_surveys():
    resp = surveys_table.scan(
        FilterExpression=Attr("sk").begins_with("SURVEY#") & Attr("answers").exists()
    )
    items = resp.get("Items", [])
    while "LastEvaluatedKey" in resp:
        resp = surveys_table.scan(
            ExclusiveStartKey=resp["LastEvaluatedKey"],
            FilterExpression=Attr("sk").begins_with("SURVEY#") & Attr("answers").exists()
        )
        items.extend(resp.get("Items", []))
    return items

def load_latest_surveys_per_user():
    """
    Keeps only latest per pk (email). Uses top-level submitted_at if present else sk.
    Only includes users with consent == True and required fields.
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

            # Consent gate (prevents matching people who didn't opt in)
            if ans.get("consent") is not True:
                continue

            # Required fields
            if not ans.get("orientation") or not ans.get("desired_signals") or not ans.get("connection_style"):
                continue

            latest[pk] = {
                "_cmp": cmp_key,
                "user_pk": pk,
                "orientation": ans.get("orientation"),
                "desired_signals": ans.get("desired_signals") or [],
                "connection_style": ans.get("connection_style"),
                "attention_bias": ans.get("attention_bias"),
                "anti_signal": ans.get("anti_signal"),
            }

    return list(latest.values())

def query_matches_for_week(week_id: str, projection: str = "user_pk, matched_user_pk"):
    """
    Query GSI for all matches in a week.
    """
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
    For repeat-avoidance: build blocklist from the previous N weeks only.
    Uses N GSI queries total.
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

def put_match(user_pk: str, week_id: str, matched_user_pk: str, score: int, exp: str):
    """
    Idempotent per-user per-week write. If rerun, ConditionExpression prevents duplicates.
    """
    matches_table.put_item(
        Item={
            "user_pk": user_pk,
            "week_id": week_id,
            "matched_user_pk": matched_user_pk,
            "score": score,
            "explain": exp,
            "status": "new",          # sender should only email "new"
            "created_at": iso_now(),
            "gsi1pk": week_id,
            "gsi1sk": score,
        },
        ConditionExpression="attribute_not_exists(user_pk) AND attribute_not_exists(week_id)"
    )

def lambda_handler(event, context):
    """
    event supports:
      - {"dry_run": true} to compute without writing matches
    """
    event = event or {}
    dry_run = bool(event.get("dry_run"))

    week_id = current_week_id()

    # Load users (1 scan)
    users = load_latest_surveys_per_user()
    if len(users) < 2:
        return {"ok": True, "week_id": week_id, "users": len(users), "records_written": 0, "pairs": 0, "dry_run": dry_run}

    by_pk = {u["user_pk"]: u for u in users}
    user_pks = list(by_pk.keys())

    # Already matched this week (1 query). This makes reruns safe.
    already_matched = build_already_matched_set(week_id)

    # Repeat avoidance from previous weeks only (N queries total)
    recent_blocks = build_recent_blocklists(REPEAT_WINDOW_WEEKS)

    matched_now = set(already_matched)
    created = 0

    # Greedy pairing in-memory
    for pk in user_pks:
        if pk in matched_now:
            continue

        u = by_pk[pk]
        best = None  # (score, other_pk)

        for other_pk in user_pks:
            if other_pk == pk or other_pk in matched_now:
                continue

            # Repeat-avoidance (symmetrical)
            if REPEAT_WINDOW_WEEKS > 0:
                if other_pk in recent_blocks.get(pk, set()):
                    continue
                if pk in recent_blocks.get(other_pk, set()):
                    continue

            v = by_pk[other_pk]
            s = pair_score(u, v)
            if best is None or s > best[0]:
                best = (s, other_pk)

        if best and best[0] >= MIN_SCORE:
            other_pk = best[1]
            score = best[0]
            exp = explain_match(u, by_pk[other_pk])

            # Mark matched in-memory even on dry-run (so we don't double-pair)
            matched_now.add(pk)
            matched_now.add(other_pk)

            if not dry_run:
                try:
                    # Write both directions so sender can fetch per-user easily
                    put_match(pk, week_id, other_pk, score, exp)
                    put_match(other_pk, week_id, pk, score, exp)
                    created += 2
                except Exception:
                    # Conditional failed (exists) or transient issues; leave as-is
                    # (We already added to matched_now to avoid pairing in this run.)
                    pass
            else:
                created += 2  # counts "would write" records in dry-run

    pairs = created // 2
    return {
        "ok": True,
        "week_id": week_id,
        "users": len(users),
        "pairs": pairs,
        "records_written": 0 if dry_run else created,
        "records_computed": created if dry_run else created,
        "already_matched_this_week": len(already_matched),
        "min_score": MIN_SCORE,
        "repeat_window_weeks": REPEAT_WINDOW_WEEKS,
        "dry_run": dry_run
    }
