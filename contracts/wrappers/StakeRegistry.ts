// TypeScript wrapper for StakeRegistry (mirrors tolk/messages.tolk and tolk/storage.tolk).
import {
    Address,
    beginCell,
    Cell,
    Contract,
    contractAddress,
    ContractProvider,
    Dictionary,
    Sender,
    SendMode,
    TupleReader,
} from '@ton/core';
import { KeyPair, sign } from '@ton/crypto';

export const Opcodes = {
    deposit: 0x7a01d001,
    addStake: 0x7a01d002,
    requestWithdraw: 0x7a01d003,
    withdraw: 0x7a01d004,
    slash: 0x7a01d005,
    claim: 0x7a01d006,
    proposeArbiter: 0x7a01d010,
    acceptArbiter: 0x7a01d011,
    proposeAdmin: 0x7a01d012,
    acceptAdmin: 0x7a01d013,
    cancelProposals: 0x7a01d014,
    payout: 0x7a01e001,
    consent: 0x74677374,
};

export const ErrCode = {
    InsufficientGas: 100,
    NotOwner: 101,
    NotArbiter: 102,
    NotAdmin: 103,
    StakeNotFound: 104,
    StakeExists: 105,
    BadAgentSignature: 106,
    BelowMinStake: 107,
    WithdrawPending: 108,
    WithdrawNotRequested: 109,
    CooldownActive: 110,
    SlashExceedsStake: 111,
    CaseAlreadyUsed: 112,
    ZeroAmount: 113,
    NoProposal: 114,
    ProposalDelayActive: 115,
    NotProposed: 116,
    NothingToClaim: 117,
    BadConfig: 118,
    BadVictim: 119,
    UnknownOp: 0xffff,
};

export type StakeRegistryConfig = {
    admin: Address;
    arbiter: Address;
    treasury: Address;
    minStake: bigint;
    cooldownSeconds: number;
    changeDelaySeconds: number;
    victimShareBps: number;
};

export function configToCell(c: StakeRegistryConfig): Cell {
    if (c.changeDelaySeconds < c.cooldownSeconds) {
        throw new Error('changeDelaySeconds must be >= cooldownSeconds (stakers must be able to exit before a new arbiter takes office)');
    }
    if (c.victimShareBps < 0 || c.victimShareBps > 10000) {
        throw new Error('victimShareBps must be within 0..10000');
    }
    return beginCell()
        .storeAddress(c.admin)
        .storeAddress(c.arbiter)
        .storeAddress(c.treasury)
        .storeCoins(c.minStake)
        .storeUint(c.cooldownSeconds, 32)
        .storeUint(c.changeDelaySeconds, 32)
        .storeUint(c.victimShareBps, 16)
        .endCell();
}

export function stakeRegistryDataCell(c: StakeRegistryConfig): Cell {
    const governance = beginCell().storeBit(0).storeBit(0).endCell(); // pendingAdmin = null, pendingArbiter = null
    const ledger = beginCell().storeBit(0).storeBit(0).storeBit(0).endCell(); // three empty maps
    return beginCell()
        .storeRef(configToCell(c))
        .storeRef(governance)
        .storeRef(ledger)
        .storeCoins(0) // totalStaked
        .storeCoins(0) // totalUnclaimed
        .endCell();
}

/// Hash the agent signs: cell(0x74677374, contract, owner, agentKey, nonce).
export function consentHash(contract: Address, owner: Address, agentKey: Buffer, nonce: bigint): Buffer {
    return beginCell()
        .storeUint(Opcodes.consent, 32)
        .storeAddress(contract)
        .storeAddress(owner)
        .storeBuffer(agentKey, 32)
        .storeUint(nonce, 64)
        .endCell()
        .hash();
}

export function signConsent(contract: Address, owner: Address, agent: KeyPair, nonce: bigint): Buffer {
    return sign(consentHash(contract, owner, agent.publicKey, nonce), agent.secretKey);
}

export type StakeInfo = {
    found: boolean;
    owner: Address | null;
    amount: bigint;
    unlockAt: number;
    withdrawing: boolean;
};

export type RequiredValues = {
    deposit: bigint;
    addStake: bigint;
    requestWithdraw: bigint;
    withdraw: bigint;
    slash: bigint;
    claim: bigint;
    governance: bigint;
};

export class StakeRegistry implements Contract {
    constructor(readonly address: Address, readonly init?: { code: Cell; data: Cell }) {}

    static createFromAddress(address: Address) {
        return new StakeRegistry(address);
    }

    static createFromConfig(config: StakeRegistryConfig, code: Cell, workchain = 0) {
        const data = stakeRegistryDataCell(config);
        const init = { code, data };
        return new StakeRegistry(contractAddress(workchain, init), init);
    }

    async sendDeploy(provider: ContractProvider, via: Sender, value: bigint) {
        await provider.internal(via, {
            value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: beginCell().endCell(),
        });
    }

    // --- message bodies ---

    static depositBody(agentKey: Buffer, nonce: bigint, signature: Buffer): Cell {
        return beginCell()
            .storeUint(Opcodes.deposit, 32)
            .storeBuffer(agentKey, 32)
            .storeUint(nonce, 64)
            .storeBuffer(signature, 64)
            .endCell();
    }

    static keyBody(op: number, agentKey: Buffer): Cell {
        return beginCell().storeUint(op, 32).storeBuffer(agentKey, 32).endCell();
    }

    static slashBody(agentKey: Buffer, amount: bigint, victim: Address, caseId: bigint): Cell {
        return beginCell()
            .storeUint(Opcodes.slash, 32)
            .storeBuffer(agentKey, 32)
            .storeCoins(amount)
            .storeAddress(victim)
            .storeUint(caseId, 64)
            .endCell();
    }

    static opBody(op: number): Cell {
        return beginCell().storeUint(op, 32).endCell();
    }

    static addressBody(op: number, addr: Address): Cell {
        return beginCell().storeUint(op, 32).storeAddress(addr).endCell();
    }

    // --- senders ---

    async sendDeposit(
        provider: ContractProvider,
        via: Sender,
        opts: { value: bigint; agentKey: Buffer; nonce: bigint; signature: Buffer },
    ) {
        await provider.internal(via, {
            value: opts.value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: StakeRegistry.depositBody(opts.agentKey, opts.nonce, opts.signature),
        });
    }

    async sendAddStake(provider: ContractProvider, via: Sender, opts: { value: bigint; agentKey: Buffer }) {
        await provider.internal(via, {
            value: opts.value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: StakeRegistry.keyBody(Opcodes.addStake, opts.agentKey),
        });
    }

    async sendRequestWithdraw(provider: ContractProvider, via: Sender, opts: { value: bigint; agentKey: Buffer }) {
        await provider.internal(via, {
            value: opts.value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: StakeRegistry.keyBody(Opcodes.requestWithdraw, opts.agentKey),
        });
    }

    async sendWithdraw(provider: ContractProvider, via: Sender, opts: { value: bigint; agentKey: Buffer }) {
        await provider.internal(via, {
            value: opts.value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: StakeRegistry.keyBody(Opcodes.withdraw, opts.agentKey),
        });
    }

    async sendSlash(
        provider: ContractProvider,
        via: Sender,
        opts: { value: bigint; agentKey: Buffer; amount: bigint; victim: Address; caseId: bigint },
    ) {
        await provider.internal(via, {
            value: opts.value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: StakeRegistry.slashBody(opts.agentKey, opts.amount, opts.victim, opts.caseId),
        });
    }

    async sendClaim(provider: ContractProvider, via: Sender, opts: { value: bigint }) {
        await provider.internal(via, {
            value: opts.value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: StakeRegistry.opBody(Opcodes.claim),
        });
    }

    async sendProposeArbiter(provider: ContractProvider, via: Sender, opts: { value: bigint; newArbiter: Address }) {
        await provider.internal(via, {
            value: opts.value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: StakeRegistry.addressBody(Opcodes.proposeArbiter, opts.newArbiter),
        });
    }

    async sendAcceptArbiter(provider: ContractProvider, via: Sender, opts: { value: bigint }) {
        await provider.internal(via, {
            value: opts.value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: StakeRegistry.opBody(Opcodes.acceptArbiter),
        });
    }

    async sendProposeAdmin(provider: ContractProvider, via: Sender, opts: { value: bigint; newAdmin: Address }) {
        await provider.internal(via, {
            value: opts.value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: StakeRegistry.addressBody(Opcodes.proposeAdmin, opts.newAdmin),
        });
    }

    async sendAcceptAdmin(provider: ContractProvider, via: Sender, opts: { value: bigint }) {
        await provider.internal(via, {
            value: opts.value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: StakeRegistry.opBody(Opcodes.acceptAdmin),
        });
    }

    async sendCancelProposals(provider: ContractProvider, via: Sender, opts: { value: bigint }) {
        await provider.internal(via, {
            value: opts.value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: StakeRegistry.opBody(Opcodes.cancelProposals),
        });
    }

    async sendRaw(provider: ContractProvider, via: Sender, opts: { value: bigint; body: Cell }) {
        await provider.internal(via, { value: opts.value, sendMode: SendMode.PAY_GAS_SEPARATELY, body: opts.body });
    }

    // --- getters ---

    async getStake(provider: ContractProvider, agentKey: Buffer): Promise<StakeInfo> {
        const res = await provider.get('get_stake', [{ type: 'int', value: BigInt('0x' + agentKey.toString('hex')) }]);
        const r = res.stack;
        return {
            found: r.readBoolean(),
            owner: r.readAddressOpt(),
            amount: r.readBigNumber(),
            unlockAt: r.readNumber(),
            withdrawing: r.readBoolean(),
        };
    }

    async getConfig(provider: ContractProvider): Promise<StakeRegistryConfig> {
        const r = (await provider.get('get_config', [])).stack;
        return {
            admin: r.readAddress(),
            arbiter: r.readAddress(),
            treasury: r.readAddress(),
            minStake: r.readBigNumber(),
            cooldownSeconds: r.readNumber(),
            changeDelaySeconds: r.readNumber(),
            victimShareBps: r.readNumber(),
        };
    }

    async getGovernance(provider: ContractProvider) {
        const r = (await provider.get('get_governance', [])).stack;
        return {
            pendingAdmin: r.readAddressOpt(),
            adminEffectiveAt: r.readNumber(),
            pendingArbiter: r.readAddressOpt(),
            arbiterEffectiveAt: r.readNumber(),
        };
    }

    async getTotals(provider: ContractProvider) {
        const r = (await provider.get('get_totals', [])).stack;
        return { totalStaked: r.readBigNumber(), totalUnclaimed: r.readBigNumber(), surplus: r.readBigNumber() };
    }

    async getUnclaimed(provider: ContractProvider, addr: Address): Promise<bigint> {
        const r = (await provider.get('get_unclaimed', [{ type: 'slice', cell: beginCell().storeAddress(addr).endCell() }])).stack;
        return r.readBigNumber();
    }

    async getIsCaseUsed(provider: ContractProvider, caseId: bigint): Promise<boolean> {
        const r = (await provider.get('is_case_used', [{ type: 'int', value: caseId }])).stack;
        return r.readBoolean();
    }

    async getRequiredValues(provider: ContractProvider): Promise<RequiredValues> {
        const r: TupleReader = (await provider.get('get_required_values', [])).stack;
        return {
            deposit: r.readBigNumber(),
            addStake: r.readBigNumber(),
            requestWithdraw: r.readBigNumber(),
            withdraw: r.readBigNumber(),
            slash: r.readBigNumber(),
            claim: r.readBigNumber(),
            governance: r.readBigNumber(),
        };
    }
}

export { Dictionary };
