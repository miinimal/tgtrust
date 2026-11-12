// StakeRegistry — Gram stake behind an anonymous accountable agent (tgtrust block 5).
// Author: Aleksandr Shcherbakov (@miinimal), MINIMALCULT. License: MIT.
//
// Invariant kept by every operation: contract balance >= totalStaked + totalUnclaimed.
// Outgoing payouts are bounceable; a bounced payout is credited to `unclaimed[dest]`
// and can be taken back with Claim, so no payout is ever lost.

tolk 1.5

import "@stdlib/gas-payments"
import "errors"
import "storage"
import "messages"

contract StakeRegistry {
    author: "Aleksandr Shcherbakov (@miinimal)"
    version: "0.1"
    description: "tgtrust stake registry: deposit, slash by arbiter verdict, withdraw after cooldown"

    storage: Storage
    incomingMessages: IncomingMessage
    thrownErrors: ErrCode
}

// Gas units per operation, measured in sandbox (tests/StakeRegistry.spec.ts prints them) and
// rounded up with a margin. The nanogram price is taken from the live network config at run time.
const GAS_DEPOSIT = 20000
const GAS_ADD_STAKE = 15000
const GAS_REQUEST_WITHDRAW = 15000
const GAS_WITHDRAW = 18000
const GAS_SLASH = 22000
const GAS_CLAIM = 15000
const GAS_GOVERNANCE = 12000

// Payout message: 32-bit opcode + 8-bit kind + 256-bit key, inline in the root cell.
const PAYOUT_BODY_BITS = 296
const PAYOUT_BODY_CELLS = 1


/// Nanograms a sender must attach for an operation that uses `gasUnits` of gas and sends
/// `payouts` payout messages (their forward fees are paid from the contract balance).
fun requiredValue(gasUnits: int, payouts: int): coins {
    val gasFee = calculateGasFee(BASECHAIN, gasUnits);
    val fwdFee = calculateForwardFee(BASECHAIN, PAYOUT_BODY_BITS, PAYOUT_BODY_CELLS);
    return gasFee + fwdFee * payouts;
}

fun sendPayout(dest: address, amount: coins, kind: int, agentKey: uint256, sendMode: int) {
    val payout = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value: amount,
        dest: dest,
        body: Payout { kind: kind as uint8, agentKey: agentKey }
    });
    payout.send(sendMode);
}

fun onInternalMessage(in: InMessage) {
    var st = Storage.load();
    val cfg = cfgOf(st);
    // Deployment guard: stakers must be able to leave before a proposed arbiter takes office.
    assert (cfg.changeDelaySeconds >= cfg.cooldownSeconds) throw ErrCode.BadConfig;
    val msg = lazy IncomingMessage.fromSlice(in.body);

    match (msg) {
        Deposit => {
            val need = requiredValue(GAS_DEPOSIT, 0);
            assert (in.valueCoins >= need) throw ErrCode.InsufficientGas;
            val amount = in.valueCoins - need;
            assert (amount >= cfg.minStake) throw ErrCode.BelowMinStake;

            val consent = DepositConsent {
                contractAddress: contract.getAddress(),
                ownerAddress: in.senderAddress,
                agentKey: msg.agentKey,
                nonce: msg.nonce,
            };
            assert (isSignatureValid(consent.toCell().hash(), msg.agentSignature as slice, msg.agentKey))
                throw ErrCode.BadAgentSignature;

            var ledger = st.ledger.load();
            assert (!ledger.stakes.exists(msg.agentKey)) throw ErrCode.StakeExists;
            ledger.stakes.set(msg.agentKey, {
                owner: in.senderAddress,
                amount: amount,
                unlockAt: 0,
                withdrawing: false,
            });
            st.ledger = ledger.toCell();
            st.totalStaked += amount;
            st.save();
        }

        AddStake => {
            val need = requiredValue(GAS_ADD_STAKE, 0);
            assert (in.valueCoins >= need) throw ErrCode.InsufficientGas;
            val amount = in.valueCoins - need;
            assert (amount > 0) throw ErrCode.ZeroAmount;

            var ledger = st.ledger.load();
            var stake = ledger.stakes.get(msg.agentKey);
            assert (stake.isFound) throw ErrCode.StakeNotFound;
            var rec = stake.loadValue();
            assert (rec.owner == in.senderAddress) throw ErrCode.NotOwner;
            assert (!rec.withdrawing) throw ErrCode.WithdrawPending;
            rec.amount += amount;
            ledger.stakes.set(msg.agentKey, rec);
            st.ledger = ledger.toCell();
            st.totalStaked += amount;
            st.save();
        }

        RequestWithdraw => {
            assert (in.valueCoins >= requiredValue(GAS_REQUEST_WITHDRAW, 0)) throw ErrCode.InsufficientGas;
            var ledger = st.ledger.load();
            var stake = ledger.stakes.get(msg.agentKey);
            assert (stake.isFound) throw ErrCode.StakeNotFound;
            var rec = stake.loadValue();
            assert (rec.owner == in.senderAddress) throw ErrCode.NotOwner;
            assert (!rec.withdrawing) throw ErrCode.WithdrawPending;
            rec.withdrawing = true;
            rec.unlockAt = (blockchain.now() + cfg.cooldownSeconds) as uint32;
            ledger.stakes.set(msg.agentKey, rec);
            st.ledger = ledger.toCell();
            st.save();
        }

        Withdraw => {
            assert (in.valueCoins >= requiredValue(GAS_WITHDRAW, 1)) throw ErrCode.InsufficientGas;
            var ledger = st.ledger.load();
            val stake = ledger.stakes.get(msg.agentKey);
            assert (stake.isFound) throw ErrCode.StakeNotFound;
            val rec = stake.loadValue();
            assert (rec.owner == in.senderAddress) throw ErrCode.NotOwner;
            assert (rec.withdrawing) throw ErrCode.WithdrawNotRequested;
            assert (blockchain.now() >= rec.unlockAt) throw ErrCode.CooldownActive;

            ledger.stakes.delete(msg.agentKey);
            st.ledger = ledger.toCell();
            st.totalStaked -= rec.amount;
            st.save();

            // Owner gets the stake plus the unspent part of the attached gas.
            sendPayout(rec.owner, rec.amount, PAYOUT_KIND_WITHDRAW, msg.agentKey,
                SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);
        }

        Slash => {
            assert (in.senderAddress == cfg.arbiter) throw ErrCode.NotArbiter;
            assert (in.valueCoins >= requiredValue(GAS_SLASH, 2)) throw ErrCode.InsufficientGas;
            assert (msg.amount > 0) throw ErrCode.ZeroAmount;
            assert (msg.victim != contract.getAddress()) throw ErrCode.BadVictim;

            var ledger = st.ledger.load();
            assert (ledger.usedCases.addIfNotExists(msg.caseId, ())) throw ErrCode.CaseAlreadyUsed;
            val stake = ledger.stakes.get(msg.agentKey);
            assert (stake.isFound) throw ErrCode.StakeNotFound;
            var rec = stake.loadValue();
            assert (msg.amount <= rec.amount) throw ErrCode.SlashExceedsStake;
            rec.amount -= msg.amount;
            ledger.stakes.set(msg.agentKey, rec);
            st.ledger = ledger.toCell();
            st.totalStaked -= msg.amount;
            st.save();

            val victimAmount = (msg.amount * cfg.victimShareBps / 10000) as coins;
            val treasuryAmount = msg.amount - victimAmount;
            if (victimAmount > 0) {
                sendPayout(msg.victim, victimAmount, PAYOUT_KIND_SLASH_VICTIM, msg.agentKey,
                    SEND_MODE_PAY_FEES_SEPARATELY);
            }
            if (treasuryAmount > 0) {
                sendPayout(cfg.treasury, treasuryAmount, PAYOUT_KIND_SLASH_TREASURY, msg.agentKey,
                    SEND_MODE_PAY_FEES_SEPARATELY);
            }
        }

        Claim => {
            assert (in.valueCoins >= requiredValue(GAS_CLAIM, 1)) throw ErrCode.InsufficientGas;
            var ledger = st.ledger.load();
            val entry = ledger.unclaimed.deleteAndGetDeleted(in.senderAddress);
            assert (entry.isFound) throw ErrCode.NothingToClaim;
            val amount = entry.loadValue();
            st.ledger = ledger.toCell();
            st.totalUnclaimed -= amount;
            st.save();
            sendPayout(in.senderAddress, amount, PAYOUT_KIND_CLAIM, 0,
                SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);
        }

        ProposeArbiter => {
            assert (in.senderAddress == cfg.admin) throw ErrCode.NotAdmin;
            assert (in.valueCoins >= requiredValue(GAS_GOVERNANCE, 0)) throw ErrCode.InsufficientGas;
            var gov = st.governance.load();
            gov.pendingArbiter = {
                newAddress: msg.newArbiter,
                effectiveAt: (blockchain.now() + cfg.changeDelaySeconds) as uint32,
            };
            st.governance = gov.toCell();
            st.save();
        }

        AcceptArbiter => {
            assert (in.valueCoins >= requiredValue(GAS_GOVERNANCE, 0)) throw ErrCode.InsufficientGas;
            var gov = st.governance.load();
            val pending = gov.pendingArbiter;
            assert (pending != null) throw ErrCode.NoProposal;
            assert (in.senderAddress == pending.newAddress) throw ErrCode.NotProposed;
            assert (blockchain.now() >= pending.effectiveAt) throw ErrCode.ProposalDelayActive;
            var newCfg = cfg;
            newCfg.arbiter = pending.newAddress;
            gov.pendingArbiter = null;
            st.config = newCfg.toCell();
            st.governance = gov.toCell();
            st.save();
        }

        ProposeAdmin => {
            assert (in.senderAddress == cfg.admin) throw ErrCode.NotAdmin;
            assert (in.valueCoins >= requiredValue(GAS_GOVERNANCE, 0)) throw ErrCode.InsufficientGas;
            var gov = st.governance.load();
            gov.pendingAdmin = {
                newAddress: msg.newAdmin,
                effectiveAt: (blockchain.now() + cfg.changeDelaySeconds) as uint32,
            };
            st.governance = gov.toCell();
            st.save();
        }

        AcceptAdmin => {
            assert (in.valueCoins >= requiredValue(GAS_GOVERNANCE, 0)) throw ErrCode.InsufficientGas;
            var gov = st.governance.load();
            val pending = gov.pendingAdmin;
            assert (pending != null) throw ErrCode.NoProposal;
            assert (in.senderAddress == pending.newAddress) throw ErrCode.NotProposed;
            assert (blockchain.now() >= pending.effectiveAt) throw ErrCode.ProposalDelayActive;
            var newCfg = cfg;
            newCfg.admin = pending.newAddress;
            gov.pendingAdmin = null;
            st.config = newCfg.toCell();
            st.governance = gov.toCell();
            st.save();
        }

        CancelProposals => {
            assert (in.senderAddress == cfg.admin) throw ErrCode.NotAdmin;
            assert (in.valueCoins >= requiredValue(GAS_GOVERNANCE, 0)) throw ErrCode.InsufficientGas;
            st.governance = Governance {}.toCell();
            st.save();
        }

        else => {
            // Empty body from admin funds the contract balance (storage fees). Everything
            // else is rejected so that the sender's value bounces back.
            assert (in.body.isEmpty() && in.senderAddress == cfg.admin) throw ErrCode.UnknownOp;
        }
    }
}

fun cfgOf(st: Storage): Config {
    return st.config.load();
}

/// A payout came back (destination refused it). Credit it to the destination so it can Claim.
/// Only coins that really arrived are credited, so a forged "bounce" cannot create value.
fun onBouncedMessage(in: InMessageBounced) {
    var st = Storage.load();
    var ledger = st.ledger.load();
    val prev = ledger.unclaimed.get(in.senderAddress);
    val before: coins = prev.isFound ? prev.loadValue() : 0;
    ledger.unclaimed.set(in.senderAddress, before + in.valueCoins);
    st.ledger = ledger.toCell();
    st.totalUnclaimed += in.valueCoins;
    st.save();
}

struct StakeReply {
    found: bool
    owner: address?
    amount: coins
    unlockAt: uint32
    withdrawing: bool
}

/// get_stake(agent_key) -> (found, owner, amount, unlock_at, withdrawing)
get fun get_stake(agentKey: uint256): StakeReply {
    val st = lazy Storage.load();
    val ledger = lazy st.ledger.load();
    val stake = ledger.stakes.get(agentKey);
    if (!stake.isFound) {
        return { found: false, owner: null, amount: 0, unlockAt: 0, withdrawing: false };
    }
    val rec = stake.loadValue();
    return { found: true, owner: rec.owner, amount: rec.amount, unlockAt: rec.unlockAt, withdrawing: rec.withdrawing };
}

/// get_config() -> (admin, arbiter, treasury, min_stake, cooldown_seconds, change_delay_seconds, victim_share_bps)
get fun get_config(): Config {
    val st = lazy Storage.load();
    return st.config.load();
}

struct GovernanceReply {
    pendingAdmin: address?
    adminEffectiveAt: uint32
    pendingArbiter: address?
    arbiterEffectiveAt: uint32
}

get fun get_governance(): GovernanceReply {
    val st = lazy Storage.load();
    val gov = st.governance.load();
    return {
        pendingAdmin: gov.pendingAdmin != null ? gov.pendingAdmin.newAddress : null,
        adminEffectiveAt: gov.pendingAdmin != null ? gov.pendingAdmin.effectiveAt : 0,
        pendingArbiter: gov.pendingArbiter != null ? gov.pendingArbiter.newAddress : null,
        arbiterEffectiveAt: gov.pendingArbiter != null ? gov.pendingArbiter.effectiveAt : 0,
    };
}

struct TotalsReply {
    totalStaked: coins
    totalUnclaimed: coins
    /// contract balance minus obligations; must stay positive for storage fees
    surplus: int
}

get fun get_totals(): TotalsReply {
    val st = lazy Storage.load();
    val obligations = st.totalStaked + st.totalUnclaimed;
    return {
        totalStaked: st.totalStaked,
        totalUnclaimed: st.totalUnclaimed,
        surplus: contract.getOriginalBalance() - obligations,
    };
}

get fun get_unclaimed(addr: address): coins {
    val st = lazy Storage.load();
    val ledger = lazy st.ledger.load();
    val entry = ledger.unclaimed.get(addr);
    return entry.isFound ? entry.loadValue() : 0;
}

get fun is_case_used(caseId: uint64): bool {
    val st = lazy Storage.load();
    val ledger = lazy st.ledger.load();
    return ledger.usedCases.exists(caseId);
}

/// Nanograms to attach for each operation at current network prices:
/// (deposit, add_stake, request_withdraw, withdraw, slash, claim, governance)
get fun get_required_values(): (coins, coins, coins, coins, coins, coins, coins) {
    return (
        requiredValue(GAS_DEPOSIT, 0),
        requiredValue(GAS_ADD_STAKE, 0),
        requiredValue(GAS_REQUEST_WITHDRAW, 0),
        requiredValue(GAS_WITHDRAW, 1),
        requiredValue(GAS_SLASH, 2),
        requiredValue(GAS_CLAIM, 1),
        requiredValue(GAS_GOVERNANCE, 0),
    );
}
