import os
import importlib.util
from pathlib import Path

os.environ.setdefault("RELAY_TABLE", "loop_relays")
os.environ.setdefault("RESEND_API_KEY", "test_key")
os.environ.setdefault("RESEND_WEBHOOK_SECRET", "whsec_dGVzdA==")

_module_path = Path(__file__).resolve().parents[1] / "lambda" / "loop_email_inbound.py"
_spec = importlib.util.spec_from_file_location("loop_email_inbound", _module_path)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def test_b64decode_loose():
    assert _mod._b64decode_loose("dGVzdA==") == b"test"


def test_extract_email():
    assert _mod._extract_email("Name <a@b.com>") == "a@b.com"


def test_svix_secret_bytes_whsec():
    secret = "whsec_dGVzdA=="
    assert _mod._svix_secret_bytes(secret) == b"test"
