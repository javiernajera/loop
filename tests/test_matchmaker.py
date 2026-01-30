import re
import importlib.util
from pathlib import Path

_MM_PATH = Path(__file__).resolve().parents[1] / "lambda" / "loop_matchmaker.py"
_spec = importlib.util.spec_from_file_location("loop_matchmaker", _MM_PATH)
_mm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mm)

build_alias = _mm.build_alias
explain_match = _mm.explain_match
generate_conversation_token = _mm.generate_conversation_token
pair_score = _mm.pair_score


def test_generate_conversation_token_is_urlsafe():
    token = generate_conversation_token()
    assert isinstance(token, str)
    assert len(token) > 0
    assert re.match(r"^[A-Za-z0-9_-]+$", token)


def test_build_alias_uses_domain():
    token = "abc123"
    alias = build_alias(token, "a")
    assert alias.startswith("c_abc123a@")
    assert "@" in alias


def test_pair_score_is_symmetric():
    u = {
        "orientation": "rebuilding",
        "desired_signals": ["grounded", "stillness"],
        "connection_style": "quiet_reflection",
        "attention_bias": "systems",
    }
    v = {
        "orientation": "rebuilding",
        "desired_signals": ["grounded"],
        "connection_style": "quiet_reflection",
        "attention_bias": "patterns",
    }
    assert pair_score(u, v) == pair_score(v, u)


def test_explain_match_returns_string():
    u = {"desired_signals": ["grounded", "stillness"]}
    v = {"desired_signals": ["grounded"]}
    out = explain_match(u, v)
    assert isinstance(out, str)
    assert len(out) > 0
