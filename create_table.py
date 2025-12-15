import json
import os
import re
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
table = dynamodb.Table("loop_users")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def _resp(status, body, origin="*"):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "POST,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        },
        "body": json.dumps(body),
    }

def lambda_handler(event, context):
    origin = os.environ.get("ALLOWED_ORIGIN", "*")

    # CORS preflight
    method = event.get("requestContext", {}).get("http", {}).get("method")
    if method == "OPTIONS":
        return _resp(200, {"ok": True}, origin=origin)

    try:
        raw = event.get("body") or "{}"
        body = json.loads(raw)
    except Exception:
        return _resp(400, {"ok": False, "error": "Invalid JSON"}, origin=origin)

    email = (body.get("email") or "").strip().lower()
    if not EMAIL_RE.match(email):
        return _resp(400, {"ok": False, "error": "Invalid email"}, origin=origin)

    now = datetime.now(timezone.utc).isoformat()

    pk = f"USER#{email}"
    sk = "PROFILE"

    # Idempotent insert: do not overwrite existing createdAt
    # If user already exists, update updatedAt only.
    try:
        table.put_item(
            Item={
                "pk": pk,
                "sk": sk,
                "email": email,
                "createdAt": now,
                "updatedAt": now,
                "status": "PENDING_SURVEY",
                "source": body.get("source", "landing_page"),
            },
            ConditionExpression="attribute_not_exists(pk)"
        )
        created = True
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        # Already exists: update updatedAt + source
        table.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression="SET updatedAt = :u, source = :s",
            ExpressionAttributeValues={":u": now, ":s": body.get("source", "landing_page")},
        )
        created = False

    return _resp(200, {"ok": True, "created": created}, origin=origin)
