# StakeRegistry — Gram stake behind an anonymous accountable agent

Part of [tgtrust](../README.md), block 5. Language: Tolk 1.5.0. Tests: TypeScript on `@ton/sandbox`.

An agent's owner locks Gram against the agent's Ed25519 key. The stake can be slashed by the arbiter on a dispute
verdict and withdrawn by the owner after a cooldown. The contract never learns who the owner is beyond a wallet
address; the link between the agent key and a Telegram account stays inside the credential of blocks 1–4.

## Layout

```
contracts/
  tolk/StakeRegistry.tolk   entrypoint, message handlers, getters
  tolk/storage.tolk         Config, Stake, Ledger, Storage
  tolk/messages.tolk        opcodes and message bodies
  tolk/errors.tolk          exit codes (100..119)
  wrappers/StakeRegistry.ts TypeScript wrapper: bodies, getters, consent signing
  tests/StakeRegistry.spec.ts  23 sandbox tests incl. every cheating scenario and a fuzz run
  scripts/build.ts          compile with @ton/tolk-js -> build/
  scripts/costs.ts          gas and storage measurement
  scripts/testnet.ts        wallet, deploy, status, live cycle on testnet
```

```
npm ci
npm run build
npm test
npx ts-node scripts/costs.ts
```

## Storage

```
Storage {
  config: Cell<Config>          admin, arbiter, treasury, minStake, cooldownSeconds, changeDelaySeconds, victimShareBps
  governance: Cell<Governance>  pendingAdmin?, pendingArbiter?   (Proposal = newAddress, effectiveAt)
  ledger: Cell<Ledger>          stakes: map<uint256 agentKey, Stake>, usedCases: map<uint64, ()>, unclaimed: map<address, coins>
  totalStaked: coins
  totalUnclaimed: coins
}
Stake { owner: address, amount: coins, unlockAt: uint32, withdrawing: bool }
```

All numbers are deployment parameters. The contract refuses every message if `changeDelaySeconds < cooldownSeconds`
(exit 118): a staker who sees a hostile arbiter proposal must be able to request and complete a withdrawal before the
new arbiter takes office.

## Operations

| op | opcode | who | effect |
| --- | --- | --- | --- |
| Deposit {agentKey, nonce, agentSignature} | 0x7a01d001 | anyone | creates the record; sender becomes owner; stake = attached value − gas requirement, must be ≥ minStake |
| AddStake {agentKey} | 0x7a01d002 | owner | adds attached value − gas requirement; rejected while withdrawing |
| RequestWithdraw {agentKey} | 0x7a01d003 | owner | sets `withdrawing`, `unlockAt = now + cooldown`; stake stays slashable |
| Withdraw {agentKey} | 0x7a01d004 | owner, after unlockAt | pays the stake to the owner (plus unspent gas), deletes the record |
| Slash {agentKey, amount, victim, caseId} | 0x7a01d005 | arbiter | amount ≤ stake; victim gets `amount·bps/10000`, treasury the rest; caseId is one-time |
| Claim | 0x7a01d006 | any address with an unclaimed balance | pays back a payout that bounced earlier |
| ProposeArbiter / ProposeAdmin {new} | 0x7a01d010 / 0x7a01d012 | admin | records a proposal effective after changeDelay |
| AcceptArbiter / AcceptAdmin | 0x7a01d011 / 0x7a01d013 | the proposed address, after the delay | applies the change |
| CancelProposals | 0x7a01d014 | admin | clears both proposals |
| empty body | — | admin | tops up the balance for storage fees; from anyone else it is rejected and bounces |

Agent consent: the agent signs `hash(cell(0x74677374, contractAddress, ownerAddress, agentKey, nonce))` with its
Ed25519 key. The signature binds the consent to one contract and one owner, so it cannot be replayed on another
contract or by another wallet, and without it nobody can "occupy" a key that is not theirs.

Getters: `get_stake(agentKey)`, `get_config()`, `get_governance()`, `get_totals()`, `get_unclaimed(address)`,
`is_case_used(caseId)`, `get_required_values()`.

## Money safety

- Invariant: `balance ≥ totalStaked + totalUnclaimed`, and both totals equal the sums of their maps. The test
  suite checks it after every test by parsing the raw storage.
- State is updated before any payout is sent, and every payout is bounceable. A bounced payout (destination has no
  code, refuses, or throws) is credited to `unclaimed[destination]` for the coins that actually came back, so it
  can be taken with `Claim`. A forged "bounce" can only credit coins that really arrived.
- Every failed operation throws before any state change, and the sender's value bounces back automatically.
- `requiredValue()` is computed from the live network config (`calculateGasFee`, `calculateForwardFee`) with
  gas-unit constants that hold a ≥2× margin over measured usage, so a sender can never under-pay the contract's
  own fees. Unspent attached value stays on the contract as a storage subsidy (except Withdraw and Claim, which
  carry the remainder back to the sender).
- Governance keys cannot move funds. A stolen admin key can only propose a new arbiter with a delay ≥ cooldown.
  A stolen arbiter key can slash: the arbiter must be a multisig in production (known limitation, by design).
- No `mainnet` deployment without a separate decision by the owner and a legal review.

## Measured costs (sandbox, mainnet config snapshot shipped with @ton/sandbox 0.45.0, 2026-11-06)

Config 21 basechain: flat 100 gas / 6667 nanogram, then 66.67 nanogram per gas unit. Config 18 basechain:
bit_price_ps 1, cell_price_ps 500 (÷65536 nanogram per second). Source: `scripts/costs.ts` run on 2026-11-06.

| operation | gas used (max in tests) | gas constant | required attached value |
| --- | --- | --- | --- |
| deposit | 7 476 | 20 000 | 0.00133 GRAM |
| add_stake | 5 026 | 15 000 | 0.00100 GRAM |
| request_withdraw | 5 013 | 15 000 | 0.00100 GRAM |
| withdraw | 7 780 | 18 000 | 0.00129 GRAM |
| slash | 9 106 | 22 000 | 0.00165 GRAM |
| claim | 5 430 | 15 000 | 0.00109 GRAM |
| governance | 5 859 | 12 000 | 0.00080 GRAM |

Storage: code 16 383 bits / 39 cells; empty data 938 bits / 4 cells; one stake record ≈ 605 bits / 2 cells.
Storage fee per year: base 0.0187 GRAM, per record 0.00077 GRAM, 1 000 records ≈ 0.79 GRAM.
Each deposit leaves ≈ 0.0008 GRAM of unspent gas on the contract, which covers about one year of that record's
storage. The admin tops up the balance with an empty message; `get_totals().surplus` shows the margin.

## Testnet

Deployed 2026-11-06 at `kQD0dNGo6GJnxq7Dc5HWcEfoBWI8UkUwZ6-w7gpwm8G11z-w`
([explorer](https://testnet.tonscan.org/address/kQD0dNGo6GJnxq7Dc5HWcEfoBWI8UkUwZ6-w7gpwm8G11z-w)) with demo parameters
(minStake 0.5 GRAM, cooldown and change delay 120 s, victim share 70 %). The live cycle deposit → request_withdraw →
slash (victim payout bounced into `unclaimed` and claimed) → withdraw is recorded in `deployments/testnet-cycle.log`.

Deployment details are written to `deployments/testnet.json` by `scripts/testnet.ts deploy`; the live cycle
log goes to `deployments/testnet-cycle.log`. Mnemonics are read from `TESTNET_MNEMONIC` / `TESTNET_VICTIM_MNEMONIC`
environment variables and are never stored in the repository.
