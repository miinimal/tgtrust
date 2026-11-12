import { Blockchain, SandboxContract, TreasuryContract, SendMessageResult } from '@ton/sandbox';
import { Address, beginCell, Cell, Dictionary, toNano, Slice } from '@ton/core';
import { KeyPair, keyPairFromSeed, getSecureRandomBytes } from '@ton/crypto';
import '@ton/test-utils';
import { compileStakeRegistry } from '../scripts/build';
import { ErrCode, Opcodes, StakeRegistry, StakeRegistryConfig, signConsent, RequiredValues } from '../wrappers/StakeRegistry';

const COOLDOWN = 7 * 24 * 3600;
const CHANGE_DELAY = 7 * 24 * 3600;
const MIN_STAKE = toNano('10');
const VICTIM_BPS = 7000;
const T0 = 1_800_000_000;

// Gas constants from tolk/StakeRegistry.tolk; tests check real usage stays below them.
const GAS_LIMITS: Record<string, number> = {
    deposit: 20000,
    addStake: 15000,
    requestWithdraw: 15000,
    withdraw: 18000,
    slash: 22000,
    claim: 15000,
    governance: 12000,
};

function randomAddress(): Address {
    return new Address(0, Buffer.from(Array.from({ length: 32 }, () => Math.floor(Math.random() * 256))));
}

async function newAgent(): Promise<KeyPair> {
    return keyPairFromSeed(await getSecureRandomBytes(32));
}

function parseLedger(data: Cell) {
    const s = data.beginParse();
    s.loadRef(); // config
    s.loadRef(); // governance
    const ledger = s.loadRef().beginParse();
    const totalStaked = s.loadCoins();
    const totalUnclaimed = s.loadCoins();
    const stakeValue = {
        serialize: () => {
            throw new Error('not needed');
        },
        parse: (v: Slice) => ({ owner: v.loadAddress(), amount: v.loadCoins(), unlockAt: v.loadUint(32), withdrawing: v.loadBit() }),
    };
    const stakes = ledger.loadDict(Dictionary.Keys.BigUint(256), stakeValue);
    const usedCases = ledger.loadDict(Dictionary.Keys.BigUint(64), { serialize: () => {}, parse: () => true });
    const unclaimed = ledger.loadDict(Dictionary.Keys.Address(), Dictionary.Values.BigVarUint(4));
    return { stakes, usedCases, unclaimed, totalStaked, totalUnclaimed };
}

describe('StakeRegistry', () => {
    let code: Cell;
    let blockchain: Blockchain;
    let admin: SandboxContract<TreasuryContract>;
    let arbiter: SandboxContract<TreasuryContract>;
    let treasury: SandboxContract<TreasuryContract>;
    let owner: SandboxContract<TreasuryContract>;
    let stranger: SandboxContract<TreasuryContract>;
    let victim: SandboxContract<TreasuryContract>;
    let registry: SandboxContract<StakeRegistry>;
    let config: StakeRegistryConfig;
    let fees: RequiredValues;
    let agent: KeyPair;
    const gasSeen: Record<string, bigint> = {};

    beforeAll(async () => {
        const r = await compileStakeRegistry();
        code = Cell.fromBase64(r.codeBoc64);
    });

    beforeEach(async () => {
        blockchain = await Blockchain.create();
        blockchain.now = T0;
        admin = await blockchain.treasury('admin');
        arbiter = await blockchain.treasury('arbiter');
        treasury = await blockchain.treasury('treasury');
        owner = await blockchain.treasury('owner', { balance: toNano('1000000') });
        stranger = await blockchain.treasury('stranger');
        victim = await blockchain.treasury('victim');
        config = {
            admin: admin.address,
            arbiter: arbiter.address,
            treasury: treasury.address,
            minStake: MIN_STAKE,
            cooldownSeconds: COOLDOWN,
            changeDelaySeconds: CHANGE_DELAY,
            victimShareBps: VICTIM_BPS,
        };
        registry = blockchain.openContract(StakeRegistry.createFromConfig(config, code));
        const deploy = await registry.sendDeploy(admin.getSender(), toNano('1'));
        expect(deploy.transactions).toHaveTransaction({ from: admin.address, to: registry.address, deploy: true, success: true });
        fees = await registry.getRequiredValues();
        agent = await newAgent();
    });

    afterEach(async () => {
        await checkInvariant();
    });

    afterAll(() => {
        console.log('gas used per operation (max seen):', Object.fromEntries(Object.entries(gasSeen).map(([k, v]) => [k, Number(v)])));
    });

    // --- helpers ---

    async function checkInvariant() {
        const c = await blockchain.getContract(registry.address);
        const state = c.accountState;
        if (!state || state.type !== 'active' || !state.state.data) throw new Error('registry not active');
        const l = parseLedger(state.state.data);
        let sumStakes = 0n;
        for (const v of l.stakes.values()) sumStakes += v.amount;
        let sumUnclaimed = 0n;
        for (const v of l.unclaimed.values()) sumUnclaimed += v;
        expect(sumStakes).toBe(l.totalStaked);
        expect(sumUnclaimed).toBe(l.totalUnclaimed);
        expect(c.balance).toBeGreaterThanOrEqual(l.totalStaked + l.totalUnclaimed);
        const totals = await registry.getTotals();
        expect(totals.totalStaked).toBe(l.totalStaked);
        expect(totals.totalUnclaimed).toBe(l.totalUnclaimed);
    }

    function recordGas(name: string, res: SendMessageResult) {
        const tx = res.transactions.find((t) => t.inMessage?.info.type === 'internal' && t.inMessage.info.dest.equals(registry.address));
        if (!tx || tx.description.type !== 'generic' || tx.description.computePhase.type !== 'vm') return;
        const g = tx.description.computePhase.gasUsed;
        if (!gasSeen[name] || g > gasSeen[name]) gasSeen[name] = g;
        expect(Number(g)).toBeLessThanOrEqual(GAS_LIMITS[name]);
    }

    async function deposit(stake: bigint, opts: { via?: SandboxContract<TreasuryContract>; key?: KeyPair; nonce?: bigint; sig?: Buffer } = {}) {
        const via = opts.via ?? owner;
        const key = opts.key ?? agent;
        const nonce = opts.nonce ?? 1n;
        const sig = opts.sig ?? signConsent(registry.address, via.address, key, nonce);
        const res = await registry.sendDeposit(via.getSender(), { value: stake + fees.deposit, agentKey: key.publicKey, nonce, signature: sig });
        return res;
    }

    async function depositOk(stake: bigint = MIN_STAKE) {
        const res = await deposit(stake);
        expect(res.transactions).toHaveTransaction({ from: owner.address, to: registry.address, success: true });
        recordGas('deposit', res);
        return res;
    }

    function expectFail(res: SendMessageResult, from: Address, exitCode: number) {
        expect(res.transactions).toHaveTransaction({ from, to: registry.address, success: false, exitCode });
        // the sender's value bounces back
        expect(res.transactions).toHaveTransaction({ from: registry.address, to: from, inMessageBounced: true });
    }

    // --- positive flows ---

    it('full cycle: deposit, add, request, withdraw', async () => {
        await depositOk();
        let s = await registry.getStake(agent.publicKey);
        expect(s.found).toBe(true);
        expect(s.owner!.equals(owner.address)).toBe(true);
        expect(s.amount).toBe(MIN_STAKE);
        expect(s.withdrawing).toBe(false);

        const add = await registry.sendAddStake(owner.getSender(), { value: toNano('5') + fees.addStake, agentKey: agent.publicKey });
        expect(add.transactions).toHaveTransaction({ from: owner.address, to: registry.address, success: true });
        recordGas('addStake', add);
        s = await registry.getStake(agent.publicKey);
        expect(s.amount).toBe(MIN_STAKE + toNano('5'));

        const req = await registry.sendRequestWithdraw(owner.getSender(), { value: fees.requestWithdraw, agentKey: agent.publicKey });
        expect(req.transactions).toHaveTransaction({ from: owner.address, to: registry.address, success: true });
        recordGas('requestWithdraw', req);
        s = await registry.getStake(agent.publicKey);
        expect(s.withdrawing).toBe(true);
        expect(s.unlockAt).toBe(T0 + COOLDOWN);

        blockchain.now = T0 + COOLDOWN;
        const before = (await blockchain.getContract(owner.address)).balance;
        const wd = await registry.sendWithdraw(owner.getSender(), { value: fees.withdraw, agentKey: agent.publicKey });
        expect(wd.transactions).toHaveTransaction({ from: owner.address, to: registry.address, success: true });
        expect(wd.transactions).toHaveTransaction({ from: registry.address, to: owner.address, op: Opcodes.payout, success: true });
        recordGas('withdraw', wd);
        const after = (await blockchain.getContract(owner.address)).balance;
        // owner gets the stake back minus fees of this one transaction (gas + forward)
        expect(after).toBeGreaterThan(before + MIN_STAKE + toNano('5') - toNano('0.05'));
        s = await registry.getStake(agent.publicKey);
        expect(s.found).toBe(false);
        expect((await registry.getTotals()).totalStaked).toBe(0n);
    });

    it('slash splits between victim and treasury, case id becomes used', async () => {
        await depositOk(toNano('100'));
        const vBefore = (await blockchain.getContract(victim.address)).balance;
        const tBefore = (await blockchain.getContract(treasury.address)).balance;
        const res = await registry.sendSlash(arbiter.getSender(), {
            value: fees.slash,
            agentKey: agent.publicKey,
            amount: toNano('40'),
            victim: victim.address,
            caseId: 42n,
        });
        expect(res.transactions).toHaveTransaction({ from: arbiter.address, to: registry.address, success: true });
        expect(res.transactions).toHaveTransaction({ from: registry.address, to: victim.address, value: toNano('28'), success: true });
        expect(res.transactions).toHaveTransaction({ from: registry.address, to: treasury.address, value: toNano('12'), success: true });
        recordGas('slash', res);
        // receivers pay their own gas for accepting the message, hence "almost"
        expect((await blockchain.getContract(victim.address)).balance).toBeGreaterThan(vBefore + toNano('27.99'));
        expect((await blockchain.getContract(treasury.address)).balance).toBeGreaterThan(tBefore + toNano('11.99'));
        const s = await registry.getStake(agent.publicKey);
        expect(s.amount).toBe(toNano('60'));
        expect(await registry.getIsCaseUsed(42n)).toBe(true);
        expect(await registry.getIsCaseUsed(43n)).toBe(false);
    });

    it('slash of the whole stake leaves a zero record; owner can still close it', async () => {
        await depositOk(toNano('20'));
        await registry.sendSlash(arbiter.getSender(), { value: fees.slash, agentKey: agent.publicKey, amount: toNano('20'), victim: victim.address, caseId: 1n });
        expect((await registry.getStake(agent.publicKey)).amount).toBe(0n);
        await registry.sendRequestWithdraw(owner.getSender(), { value: fees.requestWithdraw, agentKey: agent.publicKey });
        blockchain.now = T0 + COOLDOWN;
        const wd = await registry.sendWithdraw(owner.getSender(), { value: fees.withdraw, agentKey: agent.publicKey });
        expect(wd.transactions).toHaveTransaction({ from: owner.address, to: registry.address, success: true });
        expect((await registry.getStake(agent.publicKey)).found).toBe(false);
    });

    it('governance: propose and accept arbiter after delay; new arbiter can slash, old cannot', async () => {
        const newArbiter = await blockchain.treasury('newArbiter');
        const p = await registry.sendProposeArbiter(admin.getSender(), { value: fees.governance, newArbiter: newArbiter.address });
        expect(p.transactions).toHaveTransaction({ from: admin.address, to: registry.address, success: true });
        recordGas('governance', p);
        const g = await registry.getGovernance();
        expect(g.pendingArbiter!.equals(newArbiter.address)).toBe(true);
        expect(g.arbiterEffectiveAt).toBe(T0 + CHANGE_DELAY);

        blockchain.now = T0 + CHANGE_DELAY;
        const a = await registry.sendAcceptArbiter(newArbiter.getSender(), { value: fees.governance });
        expect(a.transactions).toHaveTransaction({ from: newArbiter.address, to: registry.address, success: true });
        recordGas('governance', a);
        expect((await registry.getConfig()).arbiter.equals(newArbiter.address)).toBe(true);
        expect((await registry.getGovernance()).pendingArbiter).toBeNull();

        await depositOk();
        const old = await registry.sendSlash(arbiter.getSender(), { value: fees.slash, agentKey: agent.publicKey, amount: 1n, victim: victim.address, caseId: 1n });
        expectFail(old, arbiter.address, ErrCode.NotArbiter);
        const fresh = await registry.sendSlash(newArbiter.getSender(), { value: fees.slash, agentKey: agent.publicKey, amount: 1n, victim: victim.address, caseId: 1n });
        expect(fresh.transactions).toHaveTransaction({ from: newArbiter.address, to: registry.address, success: true });
    });

    it('governance: propose and accept admin; cancel proposals', async () => {
        const newAdmin = await blockchain.treasury('newAdmin');
        await registry.sendProposeAdmin(admin.getSender(), { value: fees.governance, newAdmin: newAdmin.address });
        const c = await registry.sendCancelProposals(admin.getSender(), { value: fees.governance });
        expect(c.transactions).toHaveTransaction({ from: admin.address, to: registry.address, success: true });
        expect((await registry.getGovernance()).pendingAdmin).toBeNull();

        await registry.sendProposeAdmin(admin.getSender(), { value: fees.governance, newAdmin: newAdmin.address });
        blockchain.now = T0 + CHANGE_DELAY + 1;
        const a = await registry.sendAcceptAdmin(newAdmin.getSender(), { value: fees.governance });
        expect(a.transactions).toHaveTransaction({ from: newAdmin.address, to: registry.address, success: true });
        expect((await registry.getConfig()).admin.equals(newAdmin.address)).toBe(true);
        // old admin lost its rights
        const p = await registry.sendProposeArbiter(admin.getSender(), { value: fees.governance, newArbiter: stranger.address });
        expectFail(p, admin.address, ErrCode.NotAdmin);
    });

    it('admin can fund the balance with an empty message; strangers get bounced', async () => {
        const before = (await blockchain.getContract(registry.address)).balance;
        const ok = await registry.sendRaw(admin.getSender(), { value: toNano('2'), body: beginCell().endCell() });
        expect(ok.transactions).toHaveTransaction({ from: admin.address, to: registry.address, success: true });
        expect((await blockchain.getContract(registry.address)).balance).toBeGreaterThan(before + toNano('1.9'));
        const bad = await registry.sendRaw(stranger.getSender(), { value: toNano('2'), body: beginCell().endCell() });
        expectFail(bad, stranger.address, ErrCode.UnknownOp);
        const junk = await registry.sendRaw(stranger.getSender(), { value: toNano('2'), body: beginCell().storeUint(0xdeadbeef, 32).endCell() });
        expectFail(junk, stranger.address, ErrCode.UnknownOp);
    });

    // --- cheating scenarios ---

    it('deposit without a valid agent signature is rejected', async () => {
        const r1 = await deposit(MIN_STAKE, { sig: Buffer.alloc(64, 0) });
        expectFail(r1, owner.address, ErrCode.BadAgentSignature);
        const other = await newAgent();
        const r2 = await deposit(MIN_STAKE, { sig: signConsent(registry.address, owner.address, other, 1n) });
        expectFail(r2, owner.address, ErrCode.BadAgentSignature);
        expect((await registry.getStake(agent.publicKey)).found).toBe(false);
    });

    it('agent consent cannot be replayed by another owner', async () => {
        const sig = signConsent(registry.address, owner.address, agent, 7n);
        const r = await deposit(MIN_STAKE, { via: stranger, nonce: 7n, sig });
        expectFail(r, stranger.address, ErrCode.BadAgentSignature);
    });

    it('agent consent cannot be replayed on another contract', async () => {
        const other = blockchain.openContract(StakeRegistry.createFromConfig({ ...config, minStake: MIN_STAKE + 1n }, code));
        await other.sendDeploy(admin.getSender(), toNano('1'));
        const sig = signConsent(registry.address, owner.address, agent, 1n);
        const r = await other.sendDeposit(owner.getSender(), { value: toNano('20'), agentKey: agent.publicKey, nonce: 1n, signature: sig });
        expect(r.transactions).toHaveTransaction({ from: owner.address, to: other.address, success: false, exitCode: ErrCode.BadAgentSignature });
    });

    it('a second deposit for the same key is rejected even with a valid signature', async () => {
        await depositOk();
        const r = await deposit(MIN_STAKE, { via: stranger });
        expectFail(r, stranger.address, ErrCode.StakeExists);
        const r2 = await deposit(MIN_STAKE);
        expectFail(r2, owner.address, ErrCode.StakeExists);
    });

    it('add stake and withdraw by a non-owner are rejected', async () => {
        await depositOk();
        const a = await registry.sendAddStake(stranger.getSender(), { value: toNano('1') + fees.addStake, agentKey: agent.publicKey });
        expectFail(a, stranger.address, ErrCode.NotOwner);
        const r = await registry.sendRequestWithdraw(stranger.getSender(), { value: fees.requestWithdraw, agentKey: agent.publicKey });
        expectFail(r, stranger.address, ErrCode.NotOwner);
        await registry.sendRequestWithdraw(owner.getSender(), { value: fees.requestWithdraw, agentKey: agent.publicKey });
        blockchain.now = T0 + COOLDOWN;
        const w = await registry.sendWithdraw(stranger.getSender(), { value: fees.withdraw, agentKey: agent.publicKey });
        expectFail(w, stranger.address, ErrCode.NotOwner);
        expect((await registry.getStake(agent.publicKey)).amount).toBe(MIN_STAKE);
    });

    it('withdraw without a request, before the cooldown, and add stake during a pending withdrawal are rejected', async () => {
        await depositOk();
        const w0 = await registry.sendWithdraw(owner.getSender(), { value: fees.withdraw, agentKey: agent.publicKey });
        expectFail(w0, owner.address, ErrCode.WithdrawNotRequested);
        await registry.sendRequestWithdraw(owner.getSender(), { value: fees.requestWithdraw, agentKey: agent.publicKey });
        const again = await registry.sendRequestWithdraw(owner.getSender(), { value: fees.requestWithdraw, agentKey: agent.publicKey });
        expectFail(again, owner.address, ErrCode.WithdrawPending);
        const add = await registry.sendAddStake(owner.getSender(), { value: toNano('1') + fees.addStake, agentKey: agent.publicKey });
        expectFail(add, owner.address, ErrCode.WithdrawPending);
        blockchain.now = T0 + COOLDOWN - 1;
        const w1 = await registry.sendWithdraw(owner.getSender(), { value: fees.withdraw, agentKey: agent.publicKey });
        expectFail(w1, owner.address, ErrCode.CooldownActive);
        expect((await registry.getStake(agent.publicKey)).amount).toBe(MIN_STAKE);
    });

    it('operations on an unknown key are rejected', async () => {
        const r = await registry.sendRequestWithdraw(owner.getSender(), { value: fees.requestWithdraw, agentKey: agent.publicKey });
        expectFail(r, owner.address, ErrCode.StakeNotFound);
        const s = await registry.sendSlash(arbiter.getSender(), { value: fees.slash, agentKey: agent.publicKey, amount: 1n, victim: victim.address, caseId: 1n });
        expectFail(s, arbiter.address, ErrCode.StakeNotFound);
        expect(await registry.getIsCaseUsed(1n)).toBe(false);
    });

    it('slash by a non-arbiter, above the stake, zero, and with a reused case id are rejected', async () => {
        await depositOk(toNano('50'));
        const notArb = await registry.sendSlash(owner.getSender(), { value: fees.slash, agentKey: agent.publicKey, amount: 1n, victim: victim.address, caseId: 1n });
        expectFail(notArb, owner.address, ErrCode.NotArbiter);
        const adm = await registry.sendSlash(admin.getSender(), { value: fees.slash, agentKey: agent.publicKey, amount: 1n, victim: victim.address, caseId: 1n });
        expectFail(adm, admin.address, ErrCode.NotArbiter);
        const tooMuch = await registry.sendSlash(arbiter.getSender(), { value: fees.slash, agentKey: agent.publicKey, amount: toNano('50') + 1n, victim: victim.address, caseId: 1n });
        expectFail(tooMuch, arbiter.address, ErrCode.SlashExceedsStake);
        expect(await registry.getIsCaseUsed(1n)).toBe(false); // failed tx must not burn the case id
        const zero = await registry.sendSlash(arbiter.getSender(), { value: fees.slash, agentKey: agent.publicKey, amount: 0n, victim: victim.address, caseId: 1n });
        expectFail(zero, arbiter.address, ErrCode.ZeroAmount);
        const ok = await registry.sendSlash(arbiter.getSender(), { value: fees.slash, agentKey: agent.publicKey, amount: toNano('10'), victim: victim.address, caseId: 1n });
        expect(ok.transactions).toHaveTransaction({ from: arbiter.address, to: registry.address, success: true });
        const replay = await registry.sendSlash(arbiter.getSender(), { value: fees.slash, agentKey: agent.publicKey, amount: toNano('10'), victim: victim.address, caseId: 1n });
        expectFail(replay, arbiter.address, ErrCode.CaseAlreadyUsed);
        expect((await registry.getStake(agent.publicKey)).amount).toBe(toNano('40'));
    });

    it('slash to the contract itself and a misconfigured deployment are rejected', async () => {
        await depositOk();
        const self = await registry.sendSlash(arbiter.getSender(), { value: fees.slash, agentKey: agent.publicKey, amount: 1n, victim: registry.address, caseId: 1n });
        expectFail(self, arbiter.address, ErrCode.BadVictim);
        // deploy with change delay < cooldown bypassing the wrapper check: every message must fail
        const badData = beginCell()
            .storeRef(beginCell().storeAddress(admin.address).storeAddress(arbiter.address).storeAddress(treasury.address).storeCoins(MIN_STAKE).storeUint(COOLDOWN, 32).storeUint(COOLDOWN - 1, 32).storeUint(VICTIM_BPS, 16).endCell())
            .storeRef(beginCell().storeBit(0).storeBit(0).endCell())
            .storeRef(beginCell().storeBit(0).storeBit(0).storeBit(0).endCell())
            .storeCoins(0)
            .storeCoins(0)
            .endCell();
        const { contractAddress } = await import('@ton/core');
        const badAddr = contractAddress(0, { code, data: badData });
        const bad = blockchain.openContract(new StakeRegistry(badAddr, { code, data: badData }));
        const sig = signConsent(badAddr, owner.address, agent, 1n);
        const r = await bad.sendDeposit(owner.getSender(), { value: toNano('20'), agentKey: agent.publicKey, nonce: 1n, signature: sig });
        expect(r.transactions).toHaveTransaction({ from: owner.address, to: badAddr, success: false, exitCode: ErrCode.BadConfig });
    });

    it('slash during a pending withdrawal works and reduces what is withdrawn', async () => {
        await depositOk(toNano('50'));
        await registry.sendRequestWithdraw(owner.getSender(), { value: fees.requestWithdraw, agentKey: agent.publicKey });
        blockchain.now = T0 + COOLDOWN - 10;
        const s = await registry.sendSlash(arbiter.getSender(), { value: fees.slash, agentKey: agent.publicKey, amount: toNano('30'), victim: victim.address, caseId: 9n });
        expect(s.transactions).toHaveTransaction({ from: arbiter.address, to: registry.address, success: true });
        blockchain.now = T0 + COOLDOWN;
        const w = await registry.sendWithdraw(owner.getSender(), { value: fees.withdraw, agentKey: agent.publicKey });
        expect(w.transactions).toHaveTransaction({ from: registry.address, to: owner.address, op: Opcodes.payout, success: true });
        const payout = w.transactions.find((t) => t.inMessage?.info.type === 'internal' && t.inMessage.info.dest.equals(owner.address))!;
        const v = payout.inMessage!.info.type === 'internal' ? payout.inMessage!.info.value.coins : 0n;
        expect(v).toBeGreaterThanOrEqual(toNano('20'));
        expect(v).toBeLessThan(toNano('20') + fees.withdraw);
    });

    it('governance change without delay or by the wrong address is rejected', async () => {
        const newArbiter = await blockchain.treasury('newArbiter');
        const byStranger = await registry.sendProposeArbiter(stranger.getSender(), { value: fees.governance, newArbiter: stranger.address });
        expectFail(byStranger, stranger.address, ErrCode.NotAdmin);
        const byArbiter = await registry.sendProposeArbiter(arbiter.getSender(), { value: fees.governance, newArbiter: stranger.address });
        expectFail(byArbiter, arbiter.address, ErrCode.NotAdmin);
        const none = await registry.sendAcceptArbiter(newArbiter.getSender(), { value: fees.governance });
        expectFail(none, newArbiter.address, ErrCode.NoProposal);

        await registry.sendProposeArbiter(admin.getSender(), { value: fees.governance, newArbiter: newArbiter.address });
        const early = await registry.sendAcceptArbiter(newArbiter.getSender(), { value: fees.governance });
        expectFail(early, newArbiter.address, ErrCode.ProposalDelayActive);
        blockchain.now = T0 + CHANGE_DELAY;
        const wrong = await registry.sendAcceptArbiter(admin.getSender(), { value: fees.governance });
        expectFail(wrong, admin.address, ErrCode.NotProposed);
        const wrong2 = await registry.sendAcceptArbiter(stranger.getSender(), { value: fees.governance });
        expectFail(wrong2, stranger.address, ErrCode.NotProposed);
        expect((await registry.getConfig()).arbiter.equals(arbiter.address)).toBe(true);
        const cancel = await registry.sendCancelProposals(stranger.getSender(), { value: fees.governance });
        expectFail(cancel, stranger.address, ErrCode.NotAdmin);
    });

    it('bounced payout is credited to unclaimed and can be claimed; nothing is lost', async () => {
        await depositOk(toNano('100'));
        const ghost = randomAddress(); // no contract there: the payout bounces
        const res = await registry.sendSlash(arbiter.getSender(), { value: fees.slash, agentKey: agent.publicKey, amount: toNano('40'), victim: ghost, caseId: 5n });
        expect(res.transactions).toHaveTransaction({ from: arbiter.address, to: registry.address, success: true });
        expect(res.transactions).toHaveTransaction({ from: ghost, to: registry.address, inMessageBounced: true, success: true });
        const unclaimed = await registry.getUnclaimed(ghost);
        expect(unclaimed).toBeGreaterThan(toNano('27.9'));
        expect(unclaimed).toBeLessThanOrEqual(toNano('28'));
        expect((await registry.getTotals()).totalUnclaimed).toBe(unclaimed);
        // treasury part arrived normally
        expect(res.transactions).toHaveTransaction({ from: registry.address, to: treasury.address, value: toNano('12'), success: true });

        // nobody else can claim it
        const bad = await registry.sendClaim(stranger.getSender(), { value: fees.claim });
        expectFail(bad, stranger.address, ErrCode.NothingToClaim);

        // the destination (once it exists) claims it
        const ghostBalance = toNano('1');
        await blockchain.setShardAccount(ghost, (await blockchain.getContract(stranger.address)).account); // give ghost the wallet code of a treasury
        const ghostContract = await blockchain.getContract(ghost);
        ghostContract.balance = ghostBalance;
        const claimRes = await blockchain.sendMessage(
            { info: { type: 'internal', src: ghost, dest: registry.address, value: { coins: fees.claim }, bounce: true, bounced: false, ihrDisabled: true, ihrFee: 0n, forwardFee: 0n, createdLt: 0n, createdAt: 0 }, body: StakeRegistry.opBody(Opcodes.claim) } as any,
        );
        expect(claimRes.transactions).toHaveTransaction({ from: ghost, to: registry.address, success: true });
        recordGas('claim', claimRes);
        expect(claimRes.transactions).toHaveTransaction({ from: registry.address, to: ghost, op: Opcodes.payout, success: true });
        expect(await registry.getUnclaimed(ghost)).toBe(0n);
        expect((await registry.getTotals()).totalUnclaimed).toBe(0n);
    });

    it('treasury that bounces does not lose the treasury share', async () => {
        const ghostTreasury = randomAddress();
        const reg2 = blockchain.openContract(StakeRegistry.createFromConfig({ ...config, treasury: ghostTreasury }, code));
        await reg2.sendDeploy(admin.getSender(), toNano('1'));
        const f2 = await reg2.getRequiredValues();
        const sig = signConsent(reg2.address, owner.address, agent, 1n);
        await reg2.sendDeposit(owner.getSender(), { value: toNano('100') + f2.deposit, agentKey: agent.publicKey, nonce: 1n, signature: sig });
        const res = await reg2.sendSlash(arbiter.getSender(), { value: f2.slash, agentKey: agent.publicKey, amount: toNano('10'), victim: victim.address, caseId: 1n });
        expect(res.transactions).toHaveTransaction({ from: ghostTreasury, to: reg2.address, inMessageBounced: true, success: true });
        expect(await reg2.getUnclaimed(ghostTreasury)).toBeGreaterThan(toNano('2.9'));
        const c = await blockchain.getContract(reg2.address);
        const t = await reg2.getTotals();
        expect(c.balance).toBeGreaterThanOrEqual(t.totalStaked + t.totalUnclaimed);
    });

    it('insufficient attached value is rejected and bounced; state unchanged', async () => {
        const sig = signConsent(registry.address, owner.address, agent, 1n);
        const r = await registry.sendDeposit(owner.getSender(), { value: fees.deposit - 1n, agentKey: agent.publicKey, nonce: 1n, signature: sig });
        expectFail(r, owner.address, ErrCode.InsufficientGas);
        await depositOk();
        const req = await registry.sendRequestWithdraw(owner.getSender(), { value: fees.requestWithdraw - 1n, agentKey: agent.publicKey });
        expectFail(req, owner.address, ErrCode.InsufficientGas);
        const sl = await registry.sendSlash(arbiter.getSender(), { value: fees.slash - 1n, agentKey: agent.publicKey, amount: 1n, victim: victim.address, caseId: 1n });
        expectFail(sl, arbiter.address, ErrCode.InsufficientGas);
        expect(await registry.getIsCaseUsed(1n)).toBe(false);
        // a tiny value that cannot even pay for the fee computation: out of gas, still bounced, still no state change
        const tiny = await registry.sendRequestWithdraw(owner.getSender(), { value: 1000n, agentKey: agent.publicKey });
        expect(tiny.transactions).toHaveTransaction({ from: owner.address, to: registry.address, success: false });
        expect((await registry.getStake(agent.publicKey)).withdrawing).toBe(false);
    });

    it('boundary amounts: below min stake, exactly min stake, zero top-up, very large stake', async () => {
        const below = await deposit(MIN_STAKE - 1n);
        expectFail(below, owner.address, ErrCode.BelowMinStake);
        const zero = await deposit(0n);
        expectFail(zero, owner.address, ErrCode.BelowMinStake);
        const exact = await deposit(MIN_STAKE);
        expect(exact.transactions).toHaveTransaction({ from: owner.address, to: registry.address, success: true });
        expect((await registry.getStake(agent.publicKey)).amount).toBe(MIN_STAKE);
        const zeroAdd = await registry.sendAddStake(owner.getSender(), { value: fees.addStake, agentKey: agent.publicKey });
        expectFail(zeroAdd, owner.address, ErrCode.ZeroAmount);
        const big = toNano('900000');
        const bigAdd = await registry.sendAddStake(owner.getSender(), { value: big + fees.addStake, agentKey: agent.publicKey });
        expect(bigAdd.transactions).toHaveTransaction({ from: owner.address, to: registry.address, success: true });
        recordGas('addStake', bigAdd);
        expect((await registry.getStake(agent.publicKey)).amount).toBe(MIN_STAKE + big);
        expect((await registry.getTotals()).totalStaked).toBe(MIN_STAKE + big);
    });

    it('fuzz: random and truncated bodies never change state or keep the sender\'s coins', async () => {
        await depositOk(toNano('50'));
        const stateBefore = (await blockchain.getContract(registry.address)).accountState;
        const dataBefore = stateBefore && stateBefore.type === 'active' ? stateBefore.state.data!.hash().toString('hex') : '';
        const ops = Object.values(Opcodes);
        for (let i = 0; i < 150; i++) {
            const b = beginCell();
            const useKnownOp = i % 3 === 0;
            if (useKnownOp) b.storeUint(ops[i % ops.length], 32);
            const bits = Math.floor(Math.random() * 700);
            for (let k = 0; k < bits; k++) b.storeBit(Math.random() < 0.5);
            if (Math.random() < 0.3) b.storeRef(beginCell().storeUint(Math.floor(Math.random() * 2 ** 30), 32).endCell());
            const body = b.endCell();
            const sender = i % 2 === 0 ? stranger : arbiter;
            const res = await registry.sendRaw(sender.getSender(), { value: toNano('0.5'), body });
            // either the contract rejected it (and the value bounced back) or it was a valid message by chance
            const tx = res.transactions.find((t) => t.inMessage?.info.type === 'internal' && t.inMessage.info.dest.equals(registry.address))!;
            const ok = tx.description.type === 'generic' && tx.description.computePhase.type === 'vm' && tx.description.computePhase.success;
            if (!ok) {
                expect(res.transactions).toHaveTransaction({ from: registry.address, to: sender.address, inMessageBounced: true });
            }
            await checkInvariant();
        }
        const stateAfter = (await blockchain.getContract(registry.address)).accountState;
        const dataAfter = stateAfter && stateAfter.type === 'active' ? stateAfter.state.data!.hash().toString('hex') : '';
        // random bodies cannot forge signatures, ownership or arbiter rights with a stake in place: data unchanged
        // except for a possible RequestWithdraw by chance (would need the owner's address) -> none here
        expect(dataAfter).toBe(dataBefore);
        expect((await registry.getStake(agent.publicKey)).amount).toBe(toNano('50'));
    });

    it('many agents: totals track every record and withdrawals are independent', async () => {
        const agents: KeyPair[] = [];
        for (let i = 0; i < 5; i++) {
            const k = await newAgent();
            agents.push(k);
            const r = await deposit(MIN_STAKE + toNano(String(i)), { key: k, nonce: BigInt(i + 1) });
            expect(r.transactions).toHaveTransaction({ from: owner.address, to: registry.address, success: true });
            recordGas('deposit', r);
        }
        expect((await registry.getTotals()).totalStaked).toBe(MIN_STAKE * 5n + toNano('10'));
        await registry.sendRequestWithdraw(owner.getSender(), { value: fees.requestWithdraw, agentKey: agents[2].publicKey });
        blockchain.now = T0 + COOLDOWN;
        const w = await registry.sendWithdraw(owner.getSender(), { value: fees.withdraw, agentKey: agents[2].publicKey });
        expect(w.transactions).toHaveTransaction({ from: owner.address, to: registry.address, success: true });
        recordGas('withdraw', w);
        expect((await registry.getStake(agents[2].publicKey)).found).toBe(false);
        expect((await registry.getStake(agents[3].publicKey)).amount).toBe(MIN_STAKE + toNano('3'));
        expect((await registry.getTotals()).totalStaked).toBe(MIN_STAKE * 4n + toNano('8'));
    });
});
