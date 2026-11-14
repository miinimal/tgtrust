"""The stored desk vectors still match what the Python implementation does with their inputs.

desk/tests/verifier.test.mjs asserts the browser verifier gives the same answers, so together the two files
prove that desk/verifier.js and tgtrust (client, issuer, gate) agree on every vector.
"""

from __future__ import annotations

import json

from tests.desk_vectors import OUT, expectations


def test_vectors_match_python():
    data = json.loads(OUT.read_text(encoding="utf-8"))
    assert expectations(data) == data["expected"]


def test_vectors_cover_every_outcome():
    expected = json.loads(OUT.read_text(encoding="utf-8"))["expected"]
    codes = {r["error"] for r in expected["requests"]}
    assert codes >= {None, "missing_header", "bad_signature", "stale", "replay", "bad_agent", "bad_time", "bad_nonce"}
    tiers = {d["tier"]["name"] for d in expected["decisions"]}
    assert tiers == {"anonymous", "unknown", "verified", "staked", "staked+concordium"}
    creds = {(c["parsed"], c["signature_valid"]) for c in expected["credentials"]}
    assert creds == {(True, True), (True, False), (False, None)}
    assert any(c["error"] for c in expected["cards"]) and any(c["key"] for c in expected["cards"])
