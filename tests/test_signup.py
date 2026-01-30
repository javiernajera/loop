import importlib.util
from pathlib import Path

_module_path = Path(__file__).resolve().parents[1] / "lambda" / "loop_signup.py"
_spec = importlib.util.spec_from_file_location("loop_signup", _module_path)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def test_ddb_key():
    key = _mod._ddb_key("user@example.com")
    assert key == {"pk": "user@example.com", "sk": "PROFILE"}


def test_now_iso_format():
    out = _mod._now_iso_z()
    assert out.endswith("Z")
