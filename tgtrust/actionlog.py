"""Signed action log: an agent's own tamper-evident record of what it did, anchored on Concordium.

Accountability needs a record that the operator cannot quietly rewrite afterwards. Each entry says that agent key
K, as its entry number ``seq``, at ``time``, did an action of ``kind`` on an input and produced an output. Only the
SHA-256 of the input and output is in the log; the content stays with the operator, who can later show that a
given input or output is the one logged. Every entry is signed by the agent key and carries the hash of the entry
before it, so removing, reordering or editing any entry breaks every later one.

A chain alone does not stop the operator from rewriting the whole log with the same key. Anchoring does: the head
hash (agent, seq, hash of entry ``seq``) is written to Concordium in a ``RegisterData`` transaction, whose block
time is set by the chain. After an anchor, entries up to ``seq`` cannot be changed without a mismatch anyone can
check, and they existed no later than that block. Through the agent's CIS-8 binding, the key belongs to an
identity-verified Concordium account, so the record points to an accountable person without naming them.

This supports record keeping of the kind the EU AI Act asks of high-risk systems (Article 12: automatic logging
over the lifetime, traceability); it is a building block, not a compliance claim.

Entry, one JSON object per line (JSONL)::

    {"v": 1, "agent": hex32, "seq": n, "time": unix_s, "kind": str, "input": hex32, "output": hex32,
     "prev": hex32, "sig": base64url(64)}

Signed bytes: ``ENTRY_PREFIX || agent(32) || seq(u64 BE) || time(u64 BE) || len(kind)(u8) || kind ||
input(32) || output(32) || prev(32)``. Entry hash: ``sha256(signed bytes || sig)``. ``prev`` of entry 0 is 32 zero
bytes. Anchor data (86 bytes, fits RegisterData's 256): ``ANCHOR_PREFIX || agent(32) || seq(u64 BE) || hash(32)``.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import re
import struct
import time as _time
from dataclasses import dataclass
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ENTRY_PREFIX = b"tgtrust/v1/action:"
ANCHOR_PREFIX = b"tgtrust-log/v1"
ZERO = bytes(32)
_KIND = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,63}$")
_HEX32 = re.compile(r"^[0-9a-f]{64}$")
_MAX_U63 = 2**63 - 1


class LogError(ValueError):
    """The log is broken. ``seq`` is the first entry that fails (None when the problem is not one entry)."""

    def __init__(self, code: str, message: str, seq: int | None = None):
        super().__init__(message)
        self.code = code
        self.seq = seq


def digest(data: bytes | str) -> str:
    """SHA-256 hex of an input or output, the form the log stores."""
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def signed_bytes(agent: str, seq: int, time: int, kind: str, input_hash: str, output_hash: str, prev: str) -> bytes:
    if not _KIND.match(kind):
        raise ValueError("kind must be 1-64 characters of [a-z0-9._/-], starting with a letter or digit")
    for name, value in (("agent", agent), ("input", input_hash), ("output", output_hash), ("prev", prev)):
        if not isinstance(value, str) or not _HEX32.match(value):
            raise ValueError(f"{name} must be 64 lowercase hex characters")
    for name, value in (("seq", seq), ("time", time)):
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= _MAX_U63:
            raise ValueError(f"{name} must be a non-negative 63-bit integer")
    k = kind.encode()
    return (ENTRY_PREFIX + bytes.fromhex(agent) + struct.pack(">QQ", seq, time) + bytes([len(k)]) + k
            + bytes.fromhex(input_hash) + bytes.fromhex(output_hash) + bytes.fromhex(prev))


@dataclass(frozen=True)
class Entry:
    agent: str
    seq: int
    time: int
    kind: str
    input: str
    output: str
    prev: str
    sig: bytes

    def signed(self) -> bytes:
        return signed_bytes(self.agent, self.seq, self.time, self.kind, self.input, self.output, self.prev)

    @property
    def hash(self) -> str:
        return hashlib.sha256(self.signed() + self.sig).hexdigest()

    def to_dict(self) -> dict:
        return {"v": 1, "agent": self.agent, "seq": self.seq, "time": self.time, "kind": self.kind,
                "input": self.input, "output": self.output, "prev": self.prev, "sig": _b64(self.sig)}

    def to_line(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict) -> "Entry":
        if not isinstance(data, dict) or data.get("v") != 1:
            raise ValueError("not a tgtrust action log entry (v 1)")
        extra = set(data) - {"v", "agent", "seq", "time", "kind", "input", "output", "prev", "sig"}
        if extra:
            raise ValueError("unknown fields: " + ", ".join(sorted(extra)))
        sig = _unb64(data.get("sig"))
        if len(sig) != 64:
            raise ValueError("sig must be 64 bytes")
        entry = cls(data.get("agent"), data.get("seq"), data.get("time"), data.get("kind"), data.get("input"),
                    data.get("output"), data.get("prev"), sig)
        entry.signed()  # validates every field
        return entry


class ActionLog:
    """Writer side: the agent appends entries to its own log. ``agent`` is a ``tgtrust.client.AgentIdentity``."""

    def __init__(self, agent, entries: Iterable[Entry] = (), *, clock=_time.time):
        self.agent = agent
        self.entries: list[Entry] = list(entries)
        self.clock = clock
        if self.entries:
            verify(self.entries, agent.hex)

    @property
    def head(self) -> str:
        return self.entries[-1].hash if self.entries else ZERO.hex()

    def append(self, kind: str, input_data: bytes | str, output_data: bytes | str) -> Entry:
        """Log one action. Pass the content: only its SHA-256 goes into the log."""
        return self.append_hashes(kind, digest(input_data), digest(output_data))

    def append_hashes(self, kind: str, input_hash: str, output_hash: str) -> Entry:
        seq = len(self.entries)
        now = int(self.clock())
        if self.entries and now < self.entries[-1].time:
            now = self.entries[-1].time  # never let time run backwards inside one log
        msg = signed_bytes(self.agent.hex, seq, now, kind, input_hash, output_hash, self.head)
        entry = Entry(self.agent.hex, seq, now, kind, input_hash, output_hash, self.head, self.agent.sign(msg))
        self.entries.append(entry)
        return entry

    def dumps(self) -> str:
        return "".join(e.to_line() + "\n" for e in self.entries)


def loads(text: str) -> list[Entry]:
    entries = []
    for n, line in enumerate(text.splitlines()):
        if not line.strip():
            continue
        try:
            entries.append(Entry.from_dict(json.loads(line)))
        except (ValueError, TypeError) as exc:
            raise LogError("malformed", f"line {n + 1}: {exc}") from exc
    return entries


def verify(entries: list[Entry], agent: str | None = None) -> str:
    """Check signatures, numbering, time order and the hash chain. Returns the head hash; raises LogError."""
    if not entries:
        raise LogError("empty", "the log has no entries")
    key = (agent or entries[0].agent).lower()
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
    except ValueError as exc:
        raise LogError("bad_agent", "agent key must be 64 hex characters") from exc
    prev, last_time = ZERO.hex(), 0
    for i, e in enumerate(entries):
        if e.agent != key:
            raise LogError("other_agent", f"entry {i} is by another agent key", i)
        if e.seq != i:
            raise LogError("seq", f"entry {i} has seq {e.seq}: an entry is missing, repeated or reordered", i)
        if e.prev != prev:
            raise LogError("chain", f"entry {i} does not follow entry {i - 1}: the log was edited", i)
        if e.time < last_time:
            raise LogError("time", f"entry {i} is earlier than entry {i - 1}", i)
        try:
            public.verify(e.sig, e.signed())
        except InvalidSignature as exc:
            raise LogError("signature", f"entry {i} is not signed by the agent key", i) from exc
        prev, last_time = e.hash, e.time
    return prev


def find(entries: list[Entry], content: bytes | str) -> list[int]:
    """Entry numbers whose input or output is this content: lets the operator prove what was logged."""
    h = digest(content)
    return [e.seq for e in entries if h in (e.input, e.output)]


# --- anchoring on Concordium ------------------------------------------------------------------------------

def anchor_data(agent: str, seq: int, entry_hash: str) -> bytes:
    """The 86 bytes to register on Concordium (``RegisterData``) for the head after entry ``seq``."""
    if not _HEX32.match(agent or "") or not _HEX32.match(entry_hash or ""):
        raise ValueError("agent and entry hash must be 64 lowercase hex characters")
    if not isinstance(seq, int) or not 0 <= seq <= _MAX_U63:
        raise ValueError("seq must be a non-negative 63-bit integer")
    return ANCHOR_PREFIX + bytes.fromhex(agent) + struct.pack(">Q", seq) + bytes.fromhex(entry_hash)


@dataclass(frozen=True)
class Anchor:
    agent: str
    seq: int
    entry_hash: str
    tx: str | None = None
    block_time: int | None = None


def parse_anchor(data: bytes) -> Anchor:
    """Read anchor bytes back (the data of a ``RegisterData`` transaction, stored by Concordium as given)."""
    if len(data) != len(ANCHOR_PREFIX) + 72 or not data.startswith(ANCHOR_PREFIX):
        raise ValueError("not a tgtrust log anchor")
    body = data[len(ANCHOR_PREFIX):]
    return Anchor(body[:32].hex(), struct.unpack(">Q", body[32:40])[0], body[40:].hex())


def check_anchor(entries: list[Entry], anchor: Anchor) -> str:
    """Does this log agree with an anchor? Raises LogError when the anchored entry differs or is missing.

    The log may have grown since the anchor; entries after ``anchor.seq`` are covered by the next anchor only."""
    verify(entries, anchor.agent)
    if anchor.seq >= len(entries):
        raise LogError("anchor_missing", f"the log has {len(entries)} entries; the anchor covers entry {anchor.seq}")
    if entries[anchor.seq].hash != anchor.entry_hash:
        raise LogError("anchor_mismatch", f"entry {anchor.seq} differs from the anchored one: the log was rewritten",
                       anchor.seq)
    if anchor.block_time is not None and entries[anchor.seq].time > anchor.block_time + 300:
        raise LogError("anchor_time", f"entry {anchor.seq} claims a time after the block that anchored it",
                       anchor.seq)
    when = f" in transaction {anchor.tx}" if anchor.tx else ""
    return f"entries 0..{anchor.seq} match the Concordium anchor{when}"


WALLET_PROXY = {"testnet": "https://wallet-proxy.testnet.concordium.com",
                "mainnet": "https://wallet-proxy.mainnet.concordium.software"}


def read_anchor(tx: str, account: str, network: str = "testnet", *, fetch=None, max_pages: int = 10) -> Anchor:
    """Find RegisterData transaction ``tx`` among ``account``'s finalized transactions (Concordium wallet proxy)
    and parse its data as an anchor, with the block time set by the chain."""
    if not _HEX32.match(tx or ""):
        raise ValueError("transaction hash must be 64 lowercase hex characters")
    for t in _transactions(account, network, fetch, max_pages):
        if t.get("transactionHash") != tx:
            continue
        details = t.get("details") or {}
        if details.get("type") != "registerData" or details.get("outcome") != "success":
            raise LogError("anchor_read", f"transaction {tx} is not a successful RegisterData")
        anchor = parse_anchor(bytes.fromhex(details.get("registeredData", "")))
        return dataclasses.replace(anchor, tx=tx, block_time=int(t["blockTime"]))
    raise LogError("anchor_read", f"transaction {tx} not found among {account}'s transactions")


def read_anchors(account: str, agent: str, network: str = "testnet", *, fetch=None, max_pages: int = 10) -> list[Anchor]:
    """Every tgtrust log anchor for ``agent`` that ``account`` ever registered, oldest first.

    Checking a log against all of them closes the obvious gap of a single anchor: an operator who rewrites the log
    can anchor the new head too, but cannot remove the earlier anchor, and the two disagree."""
    out = []
    for t in _transactions(account, network, fetch, max_pages):
        details = t.get("details") or {}
        if details.get("type") != "registerData" or details.get("outcome") != "success":
            continue
        try:
            anchor = parse_anchor(bytes.fromhex(details.get("registeredData", "")))
        except ValueError:
            continue  # other data this account registered
        if anchor.agent == agent.lower():
            out.append(dataclasses.replace(anchor, tx=t.get("transactionHash"), block_time=int(t["blockTime"])))
    return sorted(reversed(out), key=lambda a: a.block_time)  # the proxy lists newest first


def check_anchors(entries: list[Entry], anchors: list[Anchor]) -> list[str]:
    """``check_anchor`` for every anchor; raises on the first that disagrees. An anchor for an entry the log does
    not have yet is a missing tail (entries were dropped), which also fails."""
    if not anchors:
        raise LogError("anchor_none", "no anchor for this agent was found")
    return [check_anchor(entries, a) for a in anchors]


def _transactions(account: str, network: str, fetch, max_pages: int):
    from . import concordium

    concordium.account_bytes(account)
    fetch = fetch or concordium.urllib_fetch()
    base = f"{WALLET_PROXY[network]}/v1/accTransactions/{account}?limit=1000&order=d"
    start = None
    for _ in range(max_pages):
        status, raw = fetch("GET", base + (f"&from={start}" if start is not None else ""), None,
                            {"Accept": "application/json"})
        if status != 200:
            raise LogError("anchor_read", f"wallet proxy answered HTTP {status}")
        try:
            page = json.loads(raw)
            txs = page["transactions"]
        except (ValueError, KeyError, TypeError) as exc:
            raise LogError("anchor_read", "wallet proxy reply has an unexpected shape") from exc
        yield from txs
        if len(txs) < page.get("limit", 1000) or not txs:
            return
        start = txs[-1]["id"]
    raise LogError("anchor_read", f"{account} has more than {max_pages} pages of transactions; not all were read")


# --- command line ------------------------------------------------------------------------------------------

def _read(path: str) -> list[Entry]:
    try:
        with open(path, encoding="utf-8") as fh:
            return loads(fh.read())
    except FileNotFoundError:
        return []


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    from .client import read_agent_key

    p = argparse.ArgumentParser(prog="python -m tgtrust.actionlog", description="Signed, anchored agent action log")
    sub = p.add_subparsers(dest="cmd", required=True)
    add = sub.add_parser("append", help="sign and append one action to the log (the file is created if missing)")
    add.add_argument("log")
    add.add_argument("--key-file", required=True, help="agent key file made by `python -m tgtrust.client new-key`")
    add.add_argument("--kind", required=True, help="action kind, e.g. tool.call, payment, answer")
    add.add_argument("--input", required=True, help="the action's input (text); only its SHA-256 is logged")
    add.add_argument("--output", required=True, help="the action's output (text); only its SHA-256 is logged")
    data = sub.add_parser("anchor-data", help="print the hex bytes to register on Concordium for the log's head")
    data.add_argument("log")
    chk = sub.add_parser("verify", help="check the log; with --anchor-data, also against a Concordium anchor")
    chk.add_argument("log")
    chk.add_argument("--agent", help="expected agent key (default: the key in the first entry)")
    chk.add_argument("--anchor-tx", help="hash of the anchoring RegisterData transaction")
    chk.add_argument("--anchor-account", help="the account that sent it; the anchor is then read from Concordium")
    chk.add_argument("--network", default="testnet", choices=sorted(WALLET_PROXY))
    chk.add_argument("--anchor-data", help="offline: the transaction's data as hex, instead of reading the chain")
    chk.add_argument("--block-time", type=int, help="offline: unix seconds of the block that holds the anchor")
    chk.add_argument("--find", help="also list the entries whose input or output is this text")
    args = p.parse_args(argv)

    try:
        if args.cmd == "append":
            agent = read_agent_key(args.key_file)
            log = ActionLog(agent, _read(args.log))
            entry = log.append(args.kind, args.input, args.output)
            with open(args.log, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(entry.to_line() + "\n")
            print(f"entry {entry.seq} {entry.hash}")
        elif args.cmd == "anchor-data":
            entries = _read(args.log)
            head = verify(entries)
            print(anchor_data(entries[0].agent, len(entries) - 1, head).hex())
        else:
            entries = _read(args.log)
            head = verify(entries, args.agent)
            print(f"log: {len(entries)} entries by agent {entries[0].agent}, signatures and chain valid, head {head}")
            anchor = None
            if args.anchor_data:
                anchor = dataclasses.replace(parse_anchor(bytes.fromhex(args.anchor_data)), tx=args.anchor_tx,
                                             block_time=args.block_time)
            elif args.anchor_tx and args.anchor_account:
                anchor = read_anchor(args.anchor_tx.lower(), args.anchor_account, args.network)
                print(f"anchor: entry {anchor.seq} of agent {anchor.agent}, block time {anchor.block_time} "
                      f"[source: Concordium {args.network}, transaction {anchor.tx}]")
            elif args.anchor_account:
                anchors = read_anchors(args.anchor_account, entries[0].agent, args.network)
                for line in check_anchors(entries, anchors):
                    print(line)
                print(f"all {len(anchors)} anchors by {args.anchor_account} agree with the log "
                      f"[source: Concordium {args.network}]")
            elif args.anchor_tx:
                raise ValueError("--anchor-tx needs --anchor-account (or use --anchor-data)")
            if anchor is not None:
                print(check_anchor(entries, anchor))
            if args.find is not None:
                print(f"content found in entries: {find(entries, args.find) or 'none'}")
    except (LogError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
