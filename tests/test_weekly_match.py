import importlib.util
from pathlib import Path

_WM_PATH = Path(__file__).resolve().parents[1] / "lambda" / "loop_weekly_match.py"
_spec = importlib.util.spec_from_file_location("loop_weekly_match", _WM_PATH)
_wm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_wm)

canonical_pair = _wm.canonical_pair
deterministic_alias = _wm.deterministic_alias


def test_canonical_pair_orders_lowercase():
    a, b = canonical_pair("B@EXAMPLE.COM", "a@example.com")
    assert a == "a@example.com"
    assert b == "b@example.com"


def test_deterministic_alias_is_stable():
    week_id = "2026-W05"
    a = "a@example.com"
    b = "b@example.com"
    alias1 = deterministic_alias(week_id, a, b)
    alias2 = deterministic_alias(week_id, b, a)
    assert alias1 == alias2
    assert alias1.startswith("c_")
    assert alias1.endswith("@theloopletter.com")
