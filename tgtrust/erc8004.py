"""ERC-8004 export: turns a tgtrust trust badge into an ERC-8004 agent registration file.

ERC-8004 «Trustless Agents» (https://eips.ethereum.org/EIPS/eip-8004, status Draft, created 2025-08-13,
read 2026-11-11) defines an agent registration file that EVM identity registries point to. This module
fills that file from what tgtrust actually knows about an agent and nothing else:

- the badge (``GET /v1/agents/{key}/badge``): the Telegram check, stake on TON, history;
- an operator profile: name, description, image, service endpoints (the operator's own words);
- optionally, one or more EVM registrations — accepted only with evidence (registry, agent id and the
  transaction that minted it), but listed only in ``tgtrust.evm_evidence`` as ``claimed_not_read_from_chain``.
  The standard ``registrations`` list stays empty until a real chain read exists, so the file never claims an
  on-chain identity that nobody has checked.

Field sources are documented in docs/ERC8004_EXPORT.md. The output is canonical JSON (sorted keys), so
exporting the same badge twice gives byte-identical files.

    python -m tgtrust.erc8004 --badge badge.json --profile profile.json [--evm evm.json] [--badge-url URL]

Author: Aleksandr Shcherbakov (@miinimal).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass

from .badge import LEVEL_REVOKED, LEVEL_STAKED, LEVEL_UNKNOWN, TELEGRAM_CHECK_SCOPE

# Human-readable meaning of the export field below; docs/ERC8004_EXPORT.md quotes this text (a test compares them).
ONE_ACCOUNT_FIELD_MEANING = TELEGRAM_CHECK_SCOPE

REGISTRATION_TYPE = "https://eips.ethereum.org/EIPS/eip-8004#registration-v1"
EIP_READ_DATE = "2026-11-11"
TRUST_CRYPTO_ECONOMIC = "crypto-economic"
EVM_STATUS_CLAIMED = "claimed_not_read_from_chain"

_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_TX_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
_AGENT_KEY = re.compile(r"^[0-9a-f]{64}$")


class ExportError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Profile:
    """What the operator says about the agent. ERC-8004 marks these fields mandatory."""

    name: str
    description: str
    image: str
    services: tuple[dict, ...] = ()
    x402_support: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "Profile":
        if not isinstance(data, dict):
            raise ExportError("invalid_profile", "profile must be a JSON object")
        missing = [k for k in ("name", "description", "image") if not str(data.get(k) or "").strip()]
        if missing:
            raise ExportError("missing_profile_field", f"profile needs non-empty: {', '.join(missing)}")
        services = []
        for item in data.get("services") or []:
            if not isinstance(item, dict) or not str(item.get("name") or "").strip() or not str(item.get("endpoint") or "").strip():
                raise ExportError("invalid_service", "each service needs a name and an endpoint")
            service = {"name": str(item["name"]).strip(), "endpoint": str(item["endpoint"]).strip()}
            if item.get("version"):
                service["version"] = str(item["version"])
            services.append(service)
        x402 = data.get("x402Support", False)
        if not isinstance(x402, bool):
            raise ExportError("invalid_profile", "x402Support must be true or false")
        return cls(str(data["name"]).strip(), str(data["description"]).strip(), str(data["image"]).strip(),
                   tuple(services), x402)


@dataclass(frozen=True)
class EvmRegistration:
    """An ERC-8004 identity registration on an EVM chain, with the evidence that it exists."""

    chain_id: int
    identity_registry: str
    agent_id: int
    tx_hash: str
    explorer_url: str | None = None

    @property
    def agent_registry(self) -> str:
        return f"eip155:{self.chain_id}:{self.identity_registry}"

    @classmethod
    def from_dict(cls, data: dict) -> "EvmRegistration":
        if not isinstance(data, dict):
            raise ExportError("invalid_evm_registration", "EVM registration must be a JSON object")
        chain_id, registry, agent_id, tx = (data.get(k) for k in ("chainId", "identityRegistry", "agentId", "txHash"))
        if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id <= 0:
            raise ExportError("invalid_evm_registration", "chainId must be a positive integer")
        if not isinstance(registry, str) or not _ADDRESS.match(registry):
            raise ExportError("invalid_evm_registration", "identityRegistry must be a 0x-prefixed 20-byte address")
        if not isinstance(agent_id, int) or isinstance(agent_id, bool) or agent_id < 0:
            raise ExportError("invalid_evm_registration", "agentId must be a non-negative integer")
        if not isinstance(tx, str) or not _TX_HASH.match(tx):
            raise ExportError("evm_evidence_missing",
                              "an EVM registration is exported only with the txHash that minted the agent id")
        url = data.get("explorerUrl")
        return cls(chain_id, registry.lower(), agent_id, tx.lower(), str(url) if url else None)


def _check_badge(badge: dict) -> None:
    if not isinstance(badge, dict):
        raise ExportError("invalid_badge", "badge must be a JSON object")
    for key in ("agent", "level", "unique_owner", "issuer_key_id", "registered_at", "stake", "history", "checked_at"):
        if key not in badge:
            raise ExportError("invalid_badge", f"badge field missing: {key}")
    if not isinstance(badge["agent"], str) or not _AGENT_KEY.match(badge["agent"]):
        raise ExportError("invalid_badge", "badge agent must be a 32-byte lowercase hex key")
    if badge["level"] == LEVEL_UNKNOWN or not badge["registered_at"]:
        raise ExportError("not_registered", "the agent has no tgtrust registration; nothing to export")


def _stake_view(stake: dict | None) -> dict | None:
    if stake is None:
        return None
    if stake.get("found") is None:
        return {"network": stake.get("network"), "contract": stake.get("contract"), "checked": False}
    return {
        "network": stake["network"],
        "contract": stake["contract"],
        "checked": True,
        "found": bool(stake["found"]),
        "amount_gram": stake.get("amount_gram") if stake["found"] else "0",
        "withdrawing": bool(stake.get("withdrawing")),
        "checked_at": stake.get("checked_at"),
    }


def registration_file(badge: dict, profile: Profile, evm: list[EvmRegistration] | None = None, *,
                      badge_url: str | None = None) -> dict:
    """ERC-8004 registration file for one tgtrust agent. Raises ExportError on unusable input."""
    _check_badge(badge)
    revoked = badge["level"] == LEVEL_REVOKED
    services = [dict(s) for s in profile.services]
    if badge_url:
        services.append({"name": "tgtrust-badge", "endpoint": badge_url, "version": "v1"})
    # crypto-economic trust only for a live, checked, non-withdrawing stake (the badge's «staked» level)
    supported_trust = [TRUST_CRYPTO_ECONOMIC] if badge["level"] == LEVEL_STAKED else []
    # Claimed entries are never put into the standard `registrations` field: nothing here reads the EVM chain,
    # so a generic reader must not take them for confirmed registrations. They stay in tgtrust.evm_evidence.
    claimed = sorted(evm or [], key=lambda r: (r.agent_registry, r.agent_id))
    keys = [(r.agent_registry, r.agent_id) for r in claimed]
    if len(keys) != len(set(keys)):
        raise ExportError("duplicate_evm_registration", "the same registry and agent id appear twice")
    registrations: list[dict] = []  # stays empty until a real chain read (ownerOf / tokenURI) exists
    return {
        "type": REGISTRATION_TYPE,
        "name": profile.name,
        "description": profile.description,
        "image": profile.image,
        "services": services,
        "x402Support": profile.x402_support,
        "active": not revoked,
        "registrations": registrations,
        "supportedTrust": supported_trust,
        # Extension (not defined by ERC-8004): the tgtrust facts the fields above rest on.
        "tgtrust": {
            "agent_key": badge["agent"],
            "level": badge["level"],
            # Meaning: ONE_ACCOUNT_FIELD_MEANING. Not one human, not a known operator.
            "one_account_per_issuer_epoch": bool(badge["unique_owner"]),
            "issuer_key_id": badge["issuer_key_id"],
            "registered_at": badge["registered_at"],
            "stake": _stake_view(badge["stake"]),
            "badge_checked_at": badge["checked_at"],
            "evm_evidence": [
                {"agentRegistry": r.agent_registry, "agentId": r.agent_id, "txHash": r.tx_hash,
                 # supplied by the operator; this tool does not read the EVM chain (ownerOf / tokenURI)
                 "status": EVM_STATUS_CLAIMED,
                 "verifiedOnChain": False,
                 **({"explorerUrl": r.explorer_url} if r.explorer_url else {})}
                for r in claimed
            ],
            "spec": {"eip": "https://eips.ethereum.org/EIPS/eip-8004", "status": "Draft", "read": EIP_READ_DATE},
        },
    }


def dumps(document: dict) -> str:
    """Canonical JSON: same input, same bytes."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _load(path: str) -> object:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError as exc:
        raise ExportError("missing_input", f"file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ExportError("invalid_json", f"{path}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Export a tgtrust badge as an ERC-8004 registration file")
    ap.add_argument("--badge", required=True, help="badge JSON from GET /v1/agents/{key}/badge")
    ap.add_argument("--profile", required=True, help="operator profile JSON: name, description, image, services")
    ap.add_argument("--evm", help="optional JSON list of EVM registrations with txHash evidence")
    ap.add_argument("--badge-url", help="public URL of the badge endpoint, added as a service")
    ap.add_argument("-o", "--output", help="write here instead of stdout")
    args = ap.parse_args(argv)
    try:
        badge = _load(args.badge)
        profile = Profile.from_dict(_load(args.profile))
        evm_data = _load(args.evm) if args.evm else []
        if not isinstance(evm_data, list):
            raise ExportError("invalid_evm_registration", "--evm must hold a JSON list")
        evm = [EvmRegistration.from_dict(e) for e in evm_data]
        text = dumps(registration_file(badge, profile, evm, badge_url=args.badge_url))
    except ExportError as exc:
        print(f"error {exc.code}: {exc}", file=sys.stderr)
        return 2
    if evm:
        print(f"warning: {len(evm)} EVM registration(s) are claimed, not read from the chain; they are listed only "
              f"in tgtrust.evm_evidence (status {EVM_STATUS_CLAIMED}), and `registrations` is empty", file=sys.stderr)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
