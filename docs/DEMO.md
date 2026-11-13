# Demo video script (Concordium Trusted Agents)

Target: under 2 minutes, one terminal and one browser tab, no slides. Everything below runs from a fresh clone
after `pip install -e '.[dev,server]'`. Keys and ids differ on every run; the lines to point at are named.

## 0:00–0:15 The question

Voice: "An API that sells to AI agents has to decide on every request: pay first, or credit? tgtrust answers
from evidence the agent cannot fake, and Concordium adds the one thing we cannot: an identified person behind
the key, without saying who."

Screen: README, the three facts at the top.

## 0:15–0:45 Paid API priced by trust

```bash
python examples/paid_api.py
```

Point at:

- `anonymous            403  refused`
- `verified, no stake   402  tier=verified  prepay required for this tier` (x402 v2 `PAYMENT-REQUIRED`,
  `extensions.tgtrust` says which tier and how to rise)
- `staked, call 1 … call 10  200  credit 100/1000 … 1000/1000`, then `staked, call 11  402  credit limit reached`

Voice: "Same API, three callers. Nobody states their own level: each request is signed with the agent key and the
gate reads the evidence."

## 0:45–1:15 Where the evidence comes from

```bash
python examples/two_agents.py
```

Point at:

- `second agent for alice's account refused: already_issued` (one Telegram account per issuer epoch)
- `deal recorded: … parties: 2` (both keys signed)
- `verdict: upheld -> on-chain Slash fields: {…}` and `alice badge now: {… 'upheld_against': 1 …}`

Voice: "A credential from a Telegram check, unlinkable to the account. Deals both sides signed. A dispute an
arbiter upheld, which slashes the stake on TON testnet."

## 1:15–1:45 Concordium: an identified person behind the key

```bash
python -m tgtrust.client new-key --out agent.key
python -m tgtrust.client concordium-bind --key-file agent.key --account <Concordium testnet account>
```

Point at `"namespace": "tgtrust:v1"`, `"scheme": "solana-ed25519"` and the "Next:" line: the agent key signs the
CIS-8 binding, the owner submits it from the Concordium wallet. tgtrust never holds a Concordium key.

Then (needs the real binding, see "Before recording"):

```bash
python -m tgtrust.client check --agent <agent key> --url <issuer>/v1 --concordium testnet
```

Point at the `Concordium:` lines: key bound to the account, badge valid. In the gate this is the top tier
(larger credit).

## 1:45–2:00 Close

Voice: "Telegram-checked, staked, with a record, and bound to an identified Concordium account. Read-only MCP
server and an OpenClaw skill so any agent can ask." Screen: docs/SUBMISSION.md.

## Before recording

- [ ] A tgtrust key bound on Concordium testnet from the owner's account, and its CIS-8004 agent with the badge.
- [ ] A public issuer URL for the `check` step (until then, record that step against a local issuer).
- [ ] Terminal font large, window 1280×720 or larger.
