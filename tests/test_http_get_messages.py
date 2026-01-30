import json
import hmac
import hashlib
import importlib.util
from pathlib import Path

_module_path = Path(__file__).resolve().parents[1] / "lambda" / "loop_http_get_messages.py"
_spec = importlib.util.spec_from_file_location("loop_http_get_messages", _module_path)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def test_b64url_roundtrip():
    raw = b"hello-world"
    enc = _mod._b64url_encode(raw)
    dec = _mod._b64url_decode(enc)
    assert dec == raw


def test_normalize_keeps_fields():
    item = {
        "message_id": "m1",
        "roomId": "r1",
        "userId": "u1",
        "type": "text",
        "text": "hi",
        "createdAt": "2026-01-01T00:00:00Z",
    }
    norm = _mod.normalize(item)
    assert norm["messageId"] == "m1"
    assert norm["roomId"] == "r1"


def test_verify_room_token_with_cached_secret():
    secret = "test-secret"
    _mod._SECRET_CACHE = secret

    payload = {"roomId": "room123", "exp": 4102444800}
    payload_bytes = json.dumps(payload).encode("utf-8")
    payload_b64 = _mod._b64url_encode(payload_bytes)
    sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
    sig_b64 = _mod._b64url_encode(sig)
    token = f"{payload_b64}.{sig_b64}"

    parsed = _mod.verify_room_token(token, "room123")
    assert parsed["roomId"] == "room123"


def test_cors_headers():
    headers = _mod._cors_headers()
    assert "Access-Control-Allow-Origin" in headers


def test_b64url_decode_padding():
    # "dA" is "t" in urlsafe base64 without padding
    assert _mod._b64url_decode("dA") == b"t"
