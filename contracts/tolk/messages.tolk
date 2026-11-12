/// Consent signed by the agent key. Hash of this cell is what the agent signs (Ed25519).
/// Binds the consent to this contract and to one owner so it cannot be replayed elsewhere.
struct (0x74677374) DepositConsent {
    contractAddress: address
    ownerAddress: address
    agentKey: uint256
    nonce: uint64
}

/// First deposit for an agent key. Sender becomes the owner. Attached value minus the gas
/// requirement becomes the stake; it must be >= min_stake.
struct (0x7a01d001) Deposit {
    agentKey: uint256
    nonce: uint64
    agentSignature: bits512
}

/// Owner adds to an existing stake. Rejected while a withdrawal is pending.
struct (0x7a01d002) AddStake {
    agentKey: uint256
}

/// Owner starts the cooldown. The stake stays slashable until withdraw.
struct (0x7a01d003) RequestWithdraw {
    agentKey: uint256
}

/// Owner takes the stake back after the cooldown. The record is deleted.
struct (0x7a01d004) Withdraw {
    agentKey: uint256
}

/// Arbiter executes a dispute verdict. case_id is one-time.
struct (0x7a01d005) Slash {
    agentKey: uint256
    amount: coins
    victim: address
    caseId: uint64
}

/// Any address takes back a payout that bounced earlier.
struct (0x7a01d006) Claim {
}

/// Admin proposes a new arbiter; takes effect after change_delay via AcceptArbiter.
struct (0x7a01d010) ProposeArbiter {
    newArbiter: address
}

/// Sent by the proposed arbiter after the delay.
struct (0x7a01d011) AcceptArbiter {
}

/// Admin proposes a new admin; takes effect after change_delay via AcceptAdmin.
struct (0x7a01d012) ProposeAdmin {
    newAdmin: address
}

/// Sent by the proposed admin after the delay.
struct (0x7a01d013) AcceptAdmin {
}

/// Admin cancels both pending proposals.
struct (0x7a01d014) CancelProposals {
}

type IncomingMessage =
    | Deposit
    | AddStake
    | RequestWithdraw
    | Withdraw
    | Slash
    | Claim
    | ProposeArbiter
    | AcceptArbiter
    | ProposeAdmin
    | AcceptAdmin
    | CancelProposals

/// Body of every outgoing payout. Bounces carry the first 256 bits, enough for the kind.
struct (0x7a01e001) Payout {
    kind: uint8
    agentKey: uint256
}

const PAYOUT_KIND_WITHDRAW = 1
const PAYOUT_KIND_SLASH_VICTIM = 2
const PAYOUT_KIND_SLASH_TREASURY = 3
const PAYOUT_KIND_CLAIM = 4
