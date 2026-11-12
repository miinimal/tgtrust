/// Exit codes of StakeRegistry. Codes 64..2048 are free for contracts (TVM reserves lower values).
enum ErrCode {
    /// Attached value is below the gas requirement of the operation.
    InsufficientGas = 100,
    /// Sender is not the record owner.
    NotOwner = 101,
    /// Sender is not the arbiter.
    NotArbiter = 102,
    /// Sender is not the admin.
    NotAdmin = 103,
    /// Stake record for this agent key does not exist.
    StakeNotFound = 104,
    /// Stake record for this agent key already exists.
    StakeExists = 105,
    /// Agent consent signature is invalid.
    BadAgentSignature = 106,
    /// Deposit is below min_stake.
    BelowMinStake = 107,
    /// Operation is not allowed while a withdrawal is pending.
    WithdrawPending = 108,
    /// Withdrawal was not requested.
    WithdrawNotRequested = 109,
    /// Cooldown has not elapsed yet.
    CooldownActive = 110,
    /// Slash amount exceeds the staked amount.
    SlashExceedsStake = 111,
    /// Case id was already used.
    CaseAlreadyUsed = 112,
    /// Slash amount must be positive.
    ZeroAmount = 113,
    /// There is no pending governance proposal.
    NoProposal = 114,
    /// Proposal delay has not elapsed yet.
    ProposalDelayActive = 115,
    /// Sender is not the proposed address.
    NotProposed = 116,
    /// Nothing to claim for this address.
    NothingToClaim = 117,
    /// Deployment config is inconsistent (change delay shorter than cooldown).
    BadConfig = 118,
    /// Victim address may not be the contract itself.
    BadVictim = 119,
    /// Unknown message opcode.
    UnknownOp = 0xFFFF,
}
