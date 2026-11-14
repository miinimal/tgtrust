"""The issuer keys Trust Desk pins (desk/issuers.js) are well-formed and their key ids match the keys."""

from __future__ import annotations

import json
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from tgtrust.service import key_id

ISSUERS_JS = Path(__file__).resolve().parents[1] / "desk" / "issuers.js"


def _issuers() -> list[dict]:
    text = ISSUERS_JS.read_text(encoding="utf-8")
    body = re.search(r"Object\.freeze\((\[.*\])\);", text, re.S)
    assert body, "issuers.js must hold one frozen JSON array"
    return json.loads(body.group(1))


def test_pinned_issuers_match_their_keys():
    issuers = _issuers()
    assert issuers, "at least one issuer is pinned"
    for issuer in issuers:
        public_key = serialization.load_pem_public_key(issuer["public_key_pem"].encode())
        assert key_id(public_key) == issuer["key_id"]
        assert public_key.key_size >= 2048
        assert issuer["scheme"] == "RSABSSA-SHA384-PSSZERO-Deterministic"
        assert issuer["credential_prefix"] == "tgtrust/v1/credential:"
        assert issuer["url"].startswith("https://") and issuer["url"].endswith("/v1")
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", issuer["read_at"])
        assert "may be offline" in issuer["label"]
