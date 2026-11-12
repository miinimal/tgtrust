"""ERC-8004 export (D6.4): normal input, missing input, absent EVM registration, repeat processing."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tgtrust.erc8004 import (
    REGISTRATION_TYPE,
    EvmRegistration,
    ExportError,
    Profile,
    dumps,
    main,
    registration_file,
)

SAMPLES = Path(__file__).resolve().parents[1] / "examples" / "erc8004"
REGISTERED = json.loads((SAMPLES / "badge-registered.json").read_text())
UNREGISTERED = json.loads((SAMPLES / "badge-demo-staked-unregistered.json").read_text())
PROFILE = Profile.from_dict(json.loads((SAMPLES / "profile.json").read_text()))
EVM = {"chainId": 84532, "identityRegistry": "0x" + "ab" * 20, "agentId": 7, "txHash": "0x" + "cd" * 32}

# ERC-8004 registration-v1 top-level fields (eips.ethereum.org/EIPS/eip-8004, read 2026-11-11)
SPEC_FIELDS = {"type", "name", "description", "image", "services", "x402Support", "active", "registrations",
               "supportedTrust"}


def staked_badge() -> dict:
    badge = copy.deepcopy(REGISTERED)
    badge["level"] = "staked"
    badge["stake"].update(found=True, amount_nanogram=400_000_000, amount_gram="0.4")
    return badge


def test_sample_reproduces_expected_file(tmp_path):
    out = tmp_path / "registration.json"
    assert main(["--badge", str(SAMPLES / "badge-registered.json"), "--profile", str(SAMPLES / "profile.json"),
                 "-o", str(out)]) == 0
    assert out.read_text() == (SAMPLES / "expected-registration.json").read_text()


def test_normal_input_has_every_spec_field_and_sources():
    doc = registration_file(REGISTERED, PROFILE)
    assert SPEC_FIELDS <= set(doc)
    assert doc["type"] == REGISTRATION_TYPE
    assert doc["active"] is True
    assert doc["supportedTrust"] == []  # verified owner, no live stake → no crypto-economic claim
    assert doc["tgtrust"]["agent_key"] == REGISTERED["agent"]
    assert doc["tgtrust"]["stake"]["network"] == "testnet" and doc["tgtrust"]["stake"]["found"] is False


def test_live_stake_claims_crypto_economic_trust():
    doc = registration_file(staked_badge(), PROFILE)
    assert doc["supportedTrust"] == ["crypto-economic"]
    assert doc["tgtrust"]["stake"]["amount_gram"] == "0.4"


def test_withdrawing_stake_is_not_claimed():
    badge = staked_badge()
    badge["level"] = "verified"  # the badge drops to verified while a stake is withdrawing
    badge["stake"]["withdrawing"] = True
    assert registration_file(badge, PROFILE)["supportedTrust"] == []


def test_unchecked_stake_is_not_claimed():
    badge = copy.deepcopy(REGISTERED)
    badge["stake"] = {"network": "testnet", "contract": "x", "found": None, "error": "lookup_failed"}
    doc = registration_file(badge, PROFILE)
    assert doc["supportedTrust"] == [] and doc["tgtrust"]["stake"]["checked"] is False


def test_revoked_agent_is_exported_inactive():
    badge = copy.deepcopy(REGISTERED)
    badge.update(level="revoked", unique_owner=False)
    assert registration_file(badge, PROFILE)["active"] is False


def test_unregistered_agent_is_refused_even_with_a_real_stake():
    with pytest.raises(ExportError) as exc:
        registration_file(UNREGISTERED, PROFILE)
    assert exc.value.code == "not_registered"


@pytest.mark.parametrize("field", ["name", "description", "image"])
def test_missing_profile_field(field):
    data = json.loads((SAMPLES / "profile.json").read_text())
    data[field] = " "
    with pytest.raises(ExportError) as exc:
        Profile.from_dict(data)
    assert exc.value.code == "missing_profile_field"


@pytest.mark.parametrize("field", ["agent", "level", "stake", "checked_at"])
def test_missing_badge_field(field):
    badge = copy.deepcopy(REGISTERED)
    del badge[field]
    with pytest.raises(ExportError) as exc:
        registration_file(badge, PROFILE)
    assert exc.value.code == "invalid_badge"


def test_cli_missing_file_exits_2(tmp_path, capsys):
    assert main(["--badge", str(tmp_path / "nope.json"), "--profile", str(SAMPLES / "profile.json")]) == 2
    assert "missing_input" in capsys.readouterr().err


def test_absent_evm_registration_claims_none():
    doc = registration_file(REGISTERED, PROFILE, [])
    assert doc["registrations"] == [] and doc["tgtrust"]["evm_evidence"] == []


def test_evm_registration_without_evidence_is_refused():
    data = dict(EVM)
    del data["txHash"]
    with pytest.raises(ExportError) as exc:
        EvmRegistration.from_dict(data)
    assert exc.value.code == "evm_evidence_missing"


@pytest.mark.parametrize("bad", [{"chainId": 0}, {"identityRegistry": "0x1234"}, {"agentId": -1}, {"agentId": True}])
def test_evm_registration_bad_fields(bad):
    with pytest.raises(ExportError):
        EvmRegistration.from_dict({**EVM, **bad})


def test_claimed_evm_registration_stays_out_of_registrations():
    doc = registration_file(REGISTERED, PROFILE, [EvmRegistration.from_dict(EVM)])
    assert doc["registrations"] == []
    entry = doc["tgtrust"]["evm_evidence"][0]
    assert entry["agentRegistry"] == "eip155:84532:0x" + "ab" * 20 and entry["agentId"] == 7
    assert entry["txHash"] == "0x" + "cd" * 32
    assert entry["status"] == "claimed_not_read_from_chain" and entry["verifiedOnChain"] is False


def test_cli_claimed_evm_entry_warns_on_stderr_and_stdout_is_pure_json(tmp_path, capsys):
    evm_file = tmp_path / "evm.json"
    evm_file.write_text(json.dumps([EVM]))
    assert main(["--badge", str(SAMPLES / "badge-registered.json"), "--profile", str(SAMPLES / "profile.json"),
                 "--evm", str(evm_file)]) == 0
    captured = capsys.readouterr()
    doc = json.loads(captured.out)  # the whole of stdout is JSON
    assert doc["registrations"] == []
    assert doc["tgtrust"]["evm_evidence"][0]["status"] == "claimed_not_read_from_chain"
    assert "warning" in captured.err and "claimed_not_read_from_chain" in captured.err


def test_cli_without_evm_prints_no_warning(capsys):
    assert main(["--badge", str(SAMPLES / "badge-registered.json"), "--profile", str(SAMPLES / "profile.json")]) == 0
    assert capsys.readouterr().err == ""


def test_unique_owner_is_not_exported_as_such():
    doc = registration_file(REGISTERED, PROFILE)
    assert "unique_owner" not in doc["tgtrust"]
    assert doc["tgtrust"]["one_account_per_issuer_epoch"] is True


def test_no_feedback_or_owner_verified_tag_is_emitted():
    # ERC-8004 «ownerVerified» means endpoint ownership; feedback must come from the client (research R-1111-01)
    text = dumps(registration_file(staked_badge(), PROFILE))
    assert "ownerVerified" not in text and "clientAddress" not in text and "feedback" not in text.lower()


def test_duplicate_evm_registration_is_refused():
    reg = EvmRegistration.from_dict(EVM)
    with pytest.raises(ExportError) as exc:
        registration_file(REGISTERED, PROFILE, [reg, reg])
    assert exc.value.code == "duplicate_evm_registration"


def test_repeat_processing_is_byte_identical():
    evm = [EvmRegistration.from_dict(EVM), EvmRegistration.from_dict({**EVM, "agentId": 3})]
    first = dumps(registration_file(REGISTERED, PROFILE, evm, badge_url="https://trust.example/v1/agents/x/badge"))
    second = dumps(registration_file(copy.deepcopy(REGISTERED), PROFILE, list(reversed(evm)),
                                     badge_url="https://trust.example/v1/agents/x/badge"))
    assert first == second
    assert registration_file(REGISTERED, PROFILE) == registration_file(REGISTERED, PROFILE)


def test_input_badge_is_not_modified():
    badge = copy.deepcopy(REGISTERED)
    registration_file(badge, PROFILE)
    assert badge == REGISTERED
