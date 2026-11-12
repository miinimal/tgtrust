"""Stake lookup: reads an agent's Gram stake from the StakeRegistry contract (block 5).

Uses the public toncenter HTTP API (`runGetMethod`) with the standard library only.
The badge exposes the stake amount and its state, never the owner wallet: the
contract stores the owner address, but publishing it from here would let anyone
link an agent to a wallet, which the standard is built to avoid.
"""

from __future__ import annotations

import http.client
import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

NANOGRAM = 1_000_000_000
ENDPOINTS = {
    "testnet": "https://testnet.toncenter.com/api/v2/runGetMethod",
    "mainnet": "https://toncenter.com/api/v2/runGetMethod",
}


class StakeLookupError(Exception):
    pass


@dataclass(frozen=True)
class StakeInfo:
    found: bool
    amount: int  # nanograms
    unlock_at: int
    withdrawing: bool
    checked_at: int

    def to_dict(self, network: str, contract: str) -> dict:
        return {
            "network": network,
            "contract": contract,
            "found": self.found,
            "amount_nanogram": self.amount,
            "amount_gram": f"{self.amount // NANOGRAM}.{self.amount % NANOGRAM:09d}".rstrip("0").rstrip("."),
            "withdrawing": self.withdrawing,
            "unlock_at": self.unlock_at,
            "checked_at": self.checked_at,
        }


def _stack_num(item: list) -> int:
    if item[0] != "num":
        raise StakeLookupError(f"unexpected stack item {item[0]}")
    return int(item[1], 16)


def parse_get_stake(stack: list, now: int) -> StakeInfo:
    """Parses the stack of `get_stake(agent_key)`: (found, owner?, amount, unlock_at, withdrawing)."""
    if len(stack) != 5:
        raise StakeLookupError("get_stake returned an unexpected stack")
    found = _stack_num(stack[0]) != 0
    # stack[1] is the owner address (cell) or null; deliberately not parsed
    amount = _stack_num(stack[2])
    unlock_at = _stack_num(stack[3])
    withdrawing = _stack_num(stack[4]) != 0
    if amount < 0 or unlock_at < 0:
        raise StakeLookupError("negative values in get_stake")
    return StakeInfo(found, amount, unlock_at, withdrawing, now)


Fetcher = Callable[[str, dict], dict]


def http_fetcher(timeout: float = 10.0, api_key: str | None = None) -> Fetcher:
    def fetch(url: str, payload: dict) -> dict:
        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "tgtrust/0.1"}
        if api_key:
            headers["X-API-Key"] = api_key
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raise StakeLookupError(f"toncenter HTTP {exc.code}") from exc
        except (urllib.error.URLError, http.client.HTTPException, OSError, TimeoutError, ValueError) as exc:
            raise StakeLookupError(f"toncenter unreachable: {exc}") from exc

    return fetch


class StakeReader:
    """Reads stakes from one StakeRegistry deployment with a short in-memory cache."""

    def __init__(
        self,
        contract: str,
        network: str = "testnet",
        *,
        fetcher: Fetcher | None = None,
        cache_seconds: int = 30,
        api_key: str | None = None,
        clock: Callable[[], float] = time.time,
    ):
        if network not in ENDPOINTS:
            raise ValueError("network must be testnet or mainnet")
        self.contract = contract
        self.network = network
        self._fetch = fetcher or http_fetcher(api_key=api_key)
        self._cache_seconds = cache_seconds
        self._clock = clock
        self._cache: dict[str, StakeInfo] = {}
        self._lock = threading.Lock()

    def get_stake(self, agent_public_key_hex: str) -> StakeInfo:
        key = agent_public_key_hex.lower()
        if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("agent key must be 32 bytes hex")
        now = int(self._clock())
        with self._lock:
            cached = self._cache.get(key)
            if cached and now - cached.checked_at < self._cache_seconds:
                return cached
        payload = {"address": self.contract, "method": "get_stake", "stack": [["num", "0x" + key]]}
        body = self._fetch(ENDPOINTS[self.network], payload)
        if not body.get("ok"):
            raise StakeLookupError(f"toncenter error: {body.get('error', 'unknown')}")
        result = body["result"]
        if result.get("exit_code") != 0:
            raise StakeLookupError(f"get_stake exit code {result.get('exit_code')}")
        info = parse_get_stake(result["stack"], now)
        with self._lock:
            self._cache[key] = info
        return info
