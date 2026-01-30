import importlib.util
from pathlib import Path

_module_path = Path(__file__).resolve().parents[1] / "lambda" / "loop_survey.py"
_spec = importlib.util.spec_from_file_location("loop_survey", _module_path)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def test_sha256():
    out = _mod._sha256("test")
    assert len(out) == 64


def test_resp_shape():
    resp = _mod._resp({}, 200, {"ok": True})
    assert resp["statusCode"] == 200
    assert "headers" in resp
