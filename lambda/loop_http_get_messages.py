import os
import json
import base64
import time
import hmac
import hashlib

import boto3
from boto3.dynamodb.conditions import Key

ddb = boto3.resource("dynamodb")
secrets = boto3.client("secretsmanager")

MESSAGE_TABLE = os.environ.get("MESSAGE_TABLE", "loop_messagehistory")
MESSAGE_ROOM_INDEX = os.environ.get("MESSAGE_ROOM_INDEX", "roomId-createdAt-index")
ROOM_LINK_SECRET_ARN = os.environ.get("ROOM_LINK_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:321168214871:secret:loop/room-link-KkzWLm")
ALLOW_ORIGIN = os.environ.get("ALLOW_ORIGIN", "*")

table = ddb.Table(MESSAGE_TABLE)

_SECRET_CACHE = None


def _cors_headers():
    return {
        "Access-Control-Allow-Origin": ALLOW_ORIGIN,
        "Access-Control-Allow-Headers": "content-type",
        "Access-Control-Allow-Methods": "GET,OPTIONS"
    }


def normalize(m: dict) -> dict:
    return {
        "messageId": m.get("message_id"),
        "roomId": m.get("roomId"),
        "userId": m.get("userId"),
        "type": m.get("type"),
        "text": m.get("text"),
        "createdAt": m.get("createdAt"),
        # later you can add audio fields here, etc.
    }


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _get_room_link_secret() -> str:
    """
    Reads the secret once and caches it for reuse across warm invocations.
    Secret can be either:
      - raw string, OR
      - JSON {"ROOM_LINK_SECRET": "..."}
    """
    global _SECRET_CACHE
    if _SECRET_CACHE:
        return _SECRET_CACHE

    if not ROOM_LINK_SECRET_ARN:
        raise RuntimeError("Missing env var ROOM_LINK_SECRET_ARN")

    val = secrets.get_secret_value(SecretId=ROOM_LINK_SECRET_ARN)["SecretString"]

    try:
        j = json.loads(val)
        _SECRET_CACHE = j["ROOM_LINK_SECRET"]
    except Exception:
        _SECRET_CACHE = val

    return _SECRET_CACHE


def verify_room_token(token: str, room_id: str) -> dict:
    """
    Token format: <base64url(payload_json)>.<base64url(hmac_sha256(payload_bytes))>
    payload includes: roomId, exp (unix seconds), optional userId
    """
    if not token or "." not in token:
        raise ValueError("missing token")

    payload_b64, sig_b64 = token.split(".", 1)
    payload_bytes = _b64url_decode(payload_b64)
    payload = json.loads(payload_bytes.decode("utf-8"))

    secret = _get_room_link_secret().encode("utf-8")
    expected_sig = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
    expected_sig_b64 = _b64url_encode(expected_sig)

    if not hmac.compare_digest(expected_sig_b64, sig_b64):
        raise ValueError("bad signature")

    if payload.get("roomId") != room_id:
        raise ValueError("room mismatch")

    exp = int(payload.get("exp", 0))
    if exp and int(time.time()) > exp:
        raise ValueError("expired")

    return payload


def lambda_handler(event, context):
    # Preflight
    if event.get("requestContext", {}).get("http", {}).get("method") == "OPTIONS":
        return {"statusCode": 200, "headers": _cors_headers(), "body": ""}

    path_params = event.get("pathParameters") or {}
    qs = event.get("queryStringParameters") or {}

    room_id = path_params.get("roomId") or qs.get("roomId")
    if not room_id:
        return {"statusCode": 400, "headers": _cors_headers(), "body": "Missing roomId"}

    # ✅ Require signed token
    token = qs.get("token")
    try:
        verify_room_token(token, room_id)
    except Exception:
        return {"statusCode": 403, "headers": _cors_headers(), "body": "Forbidden"}

    limit = int(qs.get("limit", "50"))
    limit = max(1, min(limit, 200))

    # Optional: fetch messages after a timestamp (ISO string)
    after = qs.get("after")  # e.g. "2025-12-18T02:33:48.604196+00:00"

    next_token = qs.get("nextToken")
    eks = None
    if next_token:
        eks = json.loads(base64.b64decode(next_token).decode("utf-8"))

    # Build query
    if after:
        key_expr = Key("roomId").eq(room_id) & Key("createdAt").gt(after)
    else:
        key_expr = Key("roomId").eq(room_id)

    query_kwargs = {
        "IndexName": MESSAGE_ROOM_INDEX,
        "KeyConditionExpression": key_expr,
        "ScanIndexForward": True,  # True = oldest->newest. Use False for newest->oldest
        "Limit": limit,
    }

    if eks:
        query_kwargs["ExclusiveStartKey"] = eks

    resp = table.query(**query_kwargs)

    items = [normalize(x) for x in resp.get("Items", [])]
    lek = resp.get("LastEvaluatedKey")

    out = {
        "roomId": room_id,
        "items": items,
        "nextToken": base64.b64encode(json.dumps(lek).encode("utf-8")).decode("utf-8") if lek else None
    }

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json", **_cors_headers()},
        "body": json.dumps(out)
    }
