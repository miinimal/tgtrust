// Testnet tooling for StakeRegistry. Mnemonics come only from environment variables:
//   TESTNET_MNEMONIC        — deployer wallet (admin, arbiter, treasury and staker in the demo)
//   TESTNET_VICTIM_MNEMONIC — second wallet that plays the victim of a slash
// Commands:
//   npx ts-node scripts/testnet.ts wallet     — print the deployer and victim addresses
//   npx ts-node scripts/testnet.ts deploy     — deploy StakeRegistry, write build/testnet-deployment.json
//   npx ts-node scripts/testnet.ts cycle      — live check: deposit, request_withdraw, slash, claim, withdraw
//   npx ts-node scripts/testnet.ts status     — print on-chain state of the deployed contract
import { Address, Cell, beginCell, internal, toNano, fromNano, SendMode, OpenedContract } from '@ton/core';
import { TonClient, WalletContractV5R1 } from '@ton/ton';
import { mnemonicToPrivateKey, keyPairFromSeed, getSecureRandomBytes, mnemonicNew, KeyPair } from '@ton/crypto';
import * as fs from 'fs';
import * as path from 'path';
import { compileStakeRegistry } from './build';
import { StakeRegistry, Opcodes, signConsent } from '../wrappers/StakeRegistry';

const ENDPOINT = process.env.TESTNET_ENDPOINT ?? 'https://testnet.toncenter.com/api/v2/jsonRPC';
const DEPLOYMENT_FILE = path.resolve(__dirname, '..', 'deployments', 'testnet.json');
const TESTNET_GLOBAL_ID = -3;
const DEMO_COOLDOWN = 120;

const client = new TonClient({ endpoint: ENDPOINT, apiKey: process.env.TONCENTER_API_KEY });

async function walletFromEnv(name: string) {
    const m = process.env[name];
    if (!m) throw new Error(`${name} is not set`);
    const kp = await mnemonicToPrivateKey(m.trim().split(/\s+/));
    const wallet = WalletContractV5R1.create({
        publicKey: kp.publicKey,
        walletId: { networkGlobalId: TESTNET_GLOBAL_ID, context: { walletVersion: 'v5r1', workchain: 0, subwalletNumber: 0 } },
    });
    return { kp, wallet, opened: client.open(wallet) };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// toncenter without an API key allows about one request per second; retry on 429
async function retry<T>(fn: () => Promise<T>, attempts = 6): Promise<T> {
    let last: unknown;
    for (let i = 0; i < attempts; i++) {
        try {
            await sleep(1200);
            return await fn();
        } catch (e) {
            last = e;
            if (!String((e as Error).message).includes('429')) throw e;
            await sleep(3000 * (i + 1));
        }
    }
    throw last;
}

async function waitSeqnoChange(opened: OpenedContract<WalletContractV5R1>, before: number) {
    for (let i = 0; i < 60; i++) {
        await sleep(3000);
        try {
            const now = await retry(() => opened.getSeqno());
            if (now > before) return;
        } catch {}
    }
    throw new Error('transaction not confirmed in 3 minutes');
}

async function send(w: Awaited<ReturnType<typeof walletFromEnv>>, to: Address, value: bigint, body: Cell | null, init?: { code: Cell; data: Cell }, bounce = true) {
    const seqno = await retry(() => w.opened.getSeqno());
    await retry(() => w.opened.sendTransfer({
        seqno,
        secretKey: w.kp.secretKey,
        sendMode: SendMode.PAY_GAS_SEPARATELY | SendMode.IGNORE_ERRORS,
        messages: [internal({ to, value, body: body ?? undefined, init, bounce })],
    }));
    await waitSeqnoChange(w.opened, seqno);
    await sleep(8000); // let the destination transaction land before reading state
}

function loadDeployment(): { address: string; codeHash: string; deployedAt: string } {
    return JSON.parse(fs.readFileSync(DEPLOYMENT_FILE, 'utf-8'));
}

async function cmdWallet() {
    const d = await walletFromEnv('TESTNET_MNEMONIC');
    const v = await walletFromEnv('TESTNET_VICTIM_MNEMONIC');
    console.log('deployer (testnet, bounceable):', d.wallet.address.toString({ testOnly: true }));
    console.log('deployer (testnet, non-bounceable, for the faucet):', d.wallet.address.toString({ testOnly: true, bounceable: false }));
    console.log('victim:', v.wallet.address.toString({ testOnly: true }));
    try {
        console.log('deployer balance:', fromNano(await retry(() => d.opened.getBalance())), 'GRAM');
        console.log('victim balance:', fromNano(await retry(() => v.opened.getBalance())), 'GRAM');
    } catch (e) {
        console.log('balance lookup failed:', (e as Error).message);
    }
}

async function cmdNewMnemonics() {
    console.log('TESTNET_MNEMONIC="' + (await mnemonicNew()).join(' ') + '"');
    console.log('TESTNET_VICTIM_MNEMONIC="' + (await mnemonicNew()).join(' ') + '"');
}

async function cmdDeploy() {
    const d = await walletFromEnv('TESTNET_MNEMONIC');
    const compiled = await compileStakeRegistry();
    const code = Cell.fromBase64(compiled.codeBoc64);
    const me = d.wallet.address;
    const registry = StakeRegistry.createFromConfig(
        {
            admin: me,
            arbiter: me,
            treasury: me,
            minStake: toNano('0.5'),
            cooldownSeconds: DEMO_COOLDOWN,
            changeDelaySeconds: DEMO_COOLDOWN,
            victimShareBps: 7000,
        },
        code,
    );
    console.log('deploying StakeRegistry to', registry.address.toString({ testOnly: true }));
    const balance = await retry(() => d.opened.getBalance());
    console.log('deployer balance:', fromNano(balance), 'GRAM');
    if (balance < toNano('1.2')) throw new Error('need at least 1.2 testnet GRAM on the deployer wallet');
    await send(d, registry.address, toNano('0.3'), beginCell().endCell(), registry.init!, false);
    const state = await retry(() => client.getContractState(registry.address));
    console.log('state:', state.state, 'balance:', fromNano(state.balance));
    fs.mkdirSync(path.dirname(DEPLOYMENT_FILE), { recursive: true });
    fs.writeFileSync(
        DEPLOYMENT_FILE,
        JSON.stringify(
            {
                network: 'testnet',
                address: registry.address.toString({ testOnly: true }),
                addressRaw: registry.address.toRawString(),
                codeHash: compiled.codeHashHex,
                tolkVersion: compiled.tolkVersion,
                config: { minStake: '0.5', cooldownSeconds: DEMO_COOLDOWN, changeDelaySeconds: DEMO_COOLDOWN, victimShareBps: 7000 },
                deployedAt: new Date().toISOString(),
                explorer: `https://testnet.tonscan.org/address/${registry.address.toString({ testOnly: true })}`,
            },
            null,
            2,
        ),
    );
    console.log('written', DEPLOYMENT_FILE);
}

async function cmdStatus() {
    const dep = loadDeployment();
    const registry = client.open(StakeRegistry.createFromAddress(Address.parse(dep.address)));
    const state = await retry(() => client.getContractState(registry.address));
    console.log('address:', dep.address, 'state:', state.state, 'balance:', fromNano(state.balance), 'GRAM');
    const totals = await retry(() => registry.getTotals());
    console.log('totals:', { staked: fromNano(totals.totalStaked), unclaimed: fromNano(totals.totalUnclaimed), surplus: fromNano(totals.surplus) });
    const fees = await retry(() => registry.getRequiredValues());
    console.log('required values (GRAM):', Object.fromEntries(Object.entries(fees).map(([k, v]) => [k, fromNano(v)])));
    const cfg = await retry(() => registry.getConfig());
    console.log('config:', { admin: cfg.admin.toString({ testOnly: true }), minStake: fromNano(cfg.minStake), cooldown: cfg.cooldownSeconds, delay: cfg.changeDelaySeconds, bps: cfg.victimShareBps });
}

async function cmdCycle() {
    const dep = loadDeployment();
    const d = await walletFromEnv('TESTNET_MNEMONIC');
    const v = await walletFromEnv('TESTNET_VICTIM_MNEMONIC');
    const registry = client.open(StakeRegistry.createFromAddress(Address.parse(dep.address)));
    const fees = await retry(() => registry.getRequiredValues());
    const agent: KeyPair = keyPairFromSeed(await getSecureRandomBytes(32));
    const log: string[] = [];
    const note = (s: string) => {
        console.log(s);
        log.push(`${new Date().toISOString()} ${s}`);
    };

    note(`contract ${dep.address}`);
    note(`agent key ${agent.publicKey.toString('hex')}`);

    // 1. deposit 1 GRAM
    const nonce = BigInt(Date.now());
    const sig = signConsent(registry.address, d.wallet.address, agent, nonce);
    await send(d, registry.address, toNano('1') + fees.deposit, StakeRegistry.depositBody(agent.publicKey, nonce, sig));
    let s = await retry(() => registry.getStake(agent.publicKey));
    note(`after deposit: found=${s.found} amount=${fromNano(s.amount)} owner=${s.owner?.toString({ testOnly: true })}`);
    if (!s.found || s.amount !== toNano('1')) throw new Error('deposit not reflected on chain');

    // 2. request withdraw
    await send(d, registry.address, fees.requestWithdraw, StakeRegistry.keyBody(Opcodes.requestWithdraw, agent.publicKey));
    s = await retry(() => registry.getStake(agent.publicKey));
    note(`after request_withdraw: withdrawing=${s.withdrawing} unlockAt=${s.unlockAt}`);
    if (!s.withdrawing) throw new Error('withdrawal not requested on chain');

    // 3. slash 0.4 during cooldown; victim is a wallet with a balance but no code, so its share bounces into unclaimed
    const victimBalance = await retry(() => v.opened.getBalance());
    if (victimBalance === 0n) {
        await send(d, v.wallet.address, toNano('0.05'), null, undefined, false);
        note('funded victim with 0.05 GRAM (uninitialised account)');
    }
    const caseId = BigInt(Date.now());
    await send(d, registry.address, fees.slash, StakeRegistry.slashBody(agent.publicKey, toNano('0.4'), v.wallet.address, caseId));
    s = await retry(() => registry.getStake(agent.publicKey));
    const used = await retry(() => registry.getIsCaseUsed(caseId));
    const unclaimed = await retry(() => registry.getUnclaimed(v.wallet.address));
    note(`after slash: amount=${fromNano(s.amount)} caseUsed=${used} victimUnclaimed=${fromNano(unclaimed)}`);
    if (s.amount !== toNano('0.6') || !used) throw new Error('slash not reflected on chain');

    // 4. victim claims the bounced share (this also deploys the victim wallet)
    if (unclaimed > 0n) {
        await send(v, registry.address, fees.claim, StakeRegistry.opBody(Opcodes.claim));
        const left = await retry(() => registry.getUnclaimed(v.wallet.address));
        note(`after claim: victimUnclaimed=${fromNano(left)} victimBalance=${fromNano(await retry(() => v.opened.getBalance()))}`);
        if (left !== 0n) throw new Error('claim not reflected on chain');
    }

    // 5. wait for the cooldown, withdraw
    s = await retry(() => registry.getStake(agent.publicKey));
    const wait = s.unlockAt - Math.floor(Date.now() / 1000) + 5;
    if (wait > 0) {
        note(`waiting ${wait}s for the cooldown`);
        await sleep(wait * 1000);
    }
    const before = await retry(() => d.opened.getBalance());
    await send(d, registry.address, fees.withdraw, StakeRegistry.keyBody(Opcodes.withdraw, agent.publicKey));
    s = await retry(() => registry.getStake(agent.publicKey));
    const after = await retry(() => d.opened.getBalance());
    note(`after withdraw: found=${s.found} deployer balance ${fromNano(before)} -> ${fromNano(after)}`);
    if (s.found) throw new Error('withdraw not reflected on chain');
    const totals = await retry(() => registry.getTotals());
    note(`totals: staked=${fromNano(totals.totalStaked)} unclaimed=${fromNano(totals.totalUnclaimed)} surplus=${fromNano(totals.surplus)}`);
    fs.writeFileSync(path.resolve(__dirname, '..', 'deployments', 'testnet-cycle.log'), log.join('\n') + '\n');
    note('live cycle complete');
}

// Leaves a permanent demo stake on the testnet contract (for the badge demo of block 6).
async function cmdDeposit() {
    const dep = loadDeployment();
    const d = await walletFromEnv('TESTNET_MNEMONIC');
    const registry = client.open(StakeRegistry.createFromAddress(Address.parse(dep.address)));
    const fees = await retry(() => registry.getRequiredValues());
    const amount = toNano(process.argv[3] ?? '0.5');
    const seedHex = process.env.DEMO_AGENT_SEED;
    const agent = keyPairFromSeed(seedHex ? Buffer.from(seedHex, 'hex') : await getSecureRandomBytes(32));
    const nonce = BigInt(Date.now());
    const sig = signConsent(registry.address, d.wallet.address, agent, nonce);
    await send(d, registry.address, amount + fees.deposit, StakeRegistry.depositBody(agent.publicKey, nonce, sig));
    const s = await retry(() => registry.getStake(agent.publicKey));
    console.log(`agent ${agent.publicKey.toString('hex')} stake ${fromNano(s.amount)} GRAM found=${s.found}`);
}

// Executes an upheld verdict: the arbiter wallet sends Slash with the fields the issuer's /v1/disputes returns.
//   npx ts-node scripts/testnet.ts slash <agent_key_hex> <amount_gram> <victim_address> <case_id>
async function cmdSlash() {
    const [agentHex, amountGram, victim, caseIdStr] = process.argv.slice(3);
    if (!agentHex || !amountGram || !victim || !caseIdStr) throw new Error('usage: slash <agent_key_hex> <amount_gram> <victim_address> <case_id>');
    const dep = loadDeployment();
    const d = await walletFromEnv('TESTNET_MNEMONIC');
    const registry = client.open(StakeRegistry.createFromAddress(Address.parse(dep.address)));
    const fees = await retry(() => registry.getRequiredValues());
    const agentKey = Buffer.from(agentHex, 'hex');
    const caseId = BigInt(caseIdStr);
    if (await retry(() => registry.getIsCaseUsed(caseId))) throw new Error('case id already used on chain');
    const before = await retry(() => registry.getStake(agentKey));
    await send(d, registry.address, fees.slash, StakeRegistry.slashBody(agentKey, toNano(amountGram), Address.parse(victim), caseId));
    const after = await retry(() => registry.getStake(agentKey));
    const used = await retry(() => registry.getIsCaseUsed(caseId));
    console.log(`slash case ${caseId}: stake ${fromNano(before.amount)} -> ${fromNano(after.amount)} GRAM, case used=${used}`);
    if (!used || after.amount !== before.amount - toNano(amountGram)) throw new Error('slash not reflected on chain');
}

async function main() {
    const cmd = process.argv[2];
    switch (cmd) {
        case 'wallet':
            return cmdWallet();
        case 'new-mnemonics':
            return cmdNewMnemonics();
        case 'deploy':
            return cmdDeploy();
        case 'status':
            return cmdStatus();
        case 'cycle':
            return cmdCycle();
        case 'deposit':
            return cmdDeposit();
        case 'slash':
            return cmdSlash();
        default:
            throw new Error('usage: testnet.ts wallet|new-mnemonics|deploy|status|cycle');
    }
}

main().catch((e) => {
    console.error(e.message ?? e);
    process.exit(1);
});
