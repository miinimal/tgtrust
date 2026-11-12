// Prints the operation costs and the storage footprint of StakeRegistry at the sandbox's network config.
// Run: npx ts-node scripts/costs.ts
import { Blockchain } from '@ton/sandbox';
import { Cell, toNano, fromNano, Dictionary } from '@ton/core';
import { configParse18, configParseGasLimitsPrices } from '@ton/ton';
import { keyPairFromSeed, getSecureRandomBytes } from '@ton/crypto';
import { compileStakeRegistry } from './build';
import { StakeRegistry, signConsent } from '../wrappers/StakeRegistry';

async function main() {
    const code = Cell.fromBase64((await compileStakeRegistry()).codeBoc64);
    const blockchain = await Blockchain.create();
    const admin = await blockchain.treasury('admin');
    const owner = await blockchain.treasury('owner', { balance: toNano('100000') });
    const registry = blockchain.openContract(
        StakeRegistry.createFromConfig(
            {
                admin: admin.address,
                arbiter: admin.address,
                treasury: admin.address,
                minStake: toNano('10'),
                cooldownSeconds: 7 * 86400,
                changeDelaySeconds: 7 * 86400,
                victimShareBps: 7000,
            },
            code,
        ),
    );
    await registry.sendDeploy(admin.getSender(), toNano('1'));

    // network prices from the config the sandbox ships (a mainnet snapshot)
    const cfgDict = Dictionary.loadDirect(Dictionary.Keys.Int(32), Dictionary.Values.Cell(), blockchain.config.beginParse());
    const storagePrices = configParse18(cfgDict.get(18)!.beginParse())[0];
    const gas = configParseGasLimitsPrices(cfgDict.get(21)!.beginParse());
    console.log('config 21 (basechain gas): flat_gas_limit', gas.flatLimit, 'flat_gas_price', gas.flatGasPrice, 'nanogram; gas_price', Number(gas.other.gasPrice) / 65536, 'nanogram per gas unit');
    console.log('config 18 (basechain storage): bit_price_ps', storagePrices.bit_price_ps, 'cell_price_ps', storagePrices.cell_price_ps, '(/65536 = nanogram per second)');
    const sp = { bitPricePs: storagePrices.bit_price_ps, cellPricePs: storagePrices.cell_price_ps };

    const fees = await registry.getRequiredValues();
    console.log('required attached value per operation (GRAM):');
    for (const [k, v] of Object.entries(fees)) console.log(`  ${k}: ${fromNano(v)}`);

    const sizeOf = async () => {
        const c = await blockchain.getContract(registry.address);
        const st = c.accountState;
        if (!st || st.type !== 'active') throw new Error('not active');
        const data = st.state.data!;
        const stats = countCells(data);
        return stats;
    };
    const before = await sizeOf();
    const N = 100;
    for (let i = 0; i < N; i++) {
        const agent = keyPairFromSeed(await getSecureRandomBytes(32));
        const sig = signConsent(registry.address, owner.address, agent, 1n);
        await registry.sendDeposit(owner.getSender(), { value: toNano('10') + fees.deposit, agentKey: agent.publicKey, nonce: 1n, signature: sig });
    }
    const after = await sizeOf();
    const perRecordBits = (after.bits - before.bits) / N;
    const perRecordCells = (after.cells - before.cells) / N;
    const yearSec = 365n * 86400n;
    const feePerYear = (bits: number, cells: number) =>
        ((BigInt(Math.ceil(bits)) * sp.bitPricePs + BigInt(Math.ceil(cells)) * sp.cellPricePs) * yearSec) >> 16n;
    const codeStats = countCells(code);
    console.log(`data cell footprint: empty ${before.bits} bits / ${before.cells} cells; with ${N} stakes ${after.bits} bits / ${after.cells} cells`);
    console.log(`per stake record: ~${perRecordBits.toFixed(0)} bits, ~${perRecordCells.toFixed(2)} cells`);
    console.log(`code: ${codeStats.bits} bits / ${codeStats.cells} cells`);
    console.log(`storage fee per year: base (code + empty data) ${fromNano(feePerYear(before.bits + codeStats.bits, before.cells + codeStats.cells))} GRAM; per record ${fromNano(feePerYear(perRecordBits, perRecordCells))} GRAM; 1000 records ${fromNano(feePerYear(before.bits + codeStats.bits + perRecordBits * 1000, before.cells + codeStats.cells + perRecordCells * 1000))} GRAM`);
    const balance = (await blockchain.getContract(registry.address)).balance;
    const totals = await registry.getTotals();
    console.log(`after ${N} deposits: balance ${fromNano(balance)} GRAM, staked ${fromNano(totals.totalStaked)}, surplus (gas dust kept as storage subsidy) ${fromNano(totals.surplus)} GRAM`);
}

function countCells(root: Cell): { bits: number; cells: number } {
    const seen = new Set<string>();
    let bits = 0, cells = 0;
    const walk = (c: Cell) => {
        const h = c.hash().toString('hex');
        if (seen.has(h)) return;
        seen.add(h);
        cells += 1;
        bits += c.bits.length;
        for (const r of c.refs) walk(r);
    };
    walk(root);
    return { bits, cells };
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
