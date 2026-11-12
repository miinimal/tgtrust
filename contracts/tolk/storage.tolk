/// Deployment parameters. Immutable except admin/arbiter via delayed proposals.
struct Config {
    /// Governance key: proposes admin/arbiter changes, may fund the contract balance.
    admin: address
    /// Dispute verdicts: the only address allowed to slash.
    arbiter: address
    /// Receives the non-victim part of every slash.
    treasury: address
    /// Minimum first deposit per agent key (nanograms).
    minStake: coins
    /// Seconds between request_withdraw and withdraw.
    cooldownSeconds: uint32
    /// Seconds between a governance proposal and its acceptance. Must be >= cooldownSeconds.
    changeDelaySeconds: uint32
    /// Victim share of a slash in basis points (0..10000).
    victimShareBps: uint16
}

/// A pending admin or arbiter change.
struct Proposal {
    newAddress: address
    effectiveAt: uint32
}

struct Governance {
    pendingAdmin: Proposal? = null
    pendingArbiter: Proposal? = null
}

/// One stake record, keyed by the agent's Ed25519 public key.
struct Stake {
    owner: address
    amount: coins
    /// Unix time after which withdraw is allowed; 0 when no withdrawal is requested.
    unlockAt: uint32
    withdrawing: bool
}

/// Mutable ledgers kept in one referenced cell.
struct Ledger {
    stakes: map<uint256, Stake> = []
    /// One-time case ids of executed slashes.
    usedCases: map<uint64, ()> = []
    /// Payouts that bounced back; claimable by the destination address.
    unclaimed: map<address, coins> = []
}

struct Storage {
    config: Cell<Config>
    governance: Cell<Governance>
    ledger: Cell<Ledger>
    /// Sum of all stake amounts; contract balance must always cover totalStaked + totalUnclaimed.
    totalStaked: coins = 0
    totalUnclaimed: coins = 0
}

fun Storage.load() {
    return Storage.fromCell(contract.getData())
}

fun Storage.save(self) {
    contract.setData(self.toCell())
}
