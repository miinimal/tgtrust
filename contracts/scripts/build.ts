// Compiles tolk/StakeRegistry.tolk with @ton/tolk-js and writes build/StakeRegistry.compiled.json.
import { runTolkCompiler, getTolkCompilerVersion } from '@ton/tolk-js';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'tolk');
const OUT = path.join(ROOT, 'build');

export async function compileStakeRegistry() {
    const result = await runTolkCompiler({
        entrypointFileName: 'StakeRegistry.tolk',
        fsReadCallback: (p) => fs.readFileSync(path.join(SRC, p), 'utf-8'),
        withStackComments: false,
        withSrcLineComments: true,
    });
    if (result.status === 'error') {
        throw new Error(result.message);
    }
    return result;
}

async function main() {
    const version = await getTolkCompilerVersion();
    const result = await compileStakeRegistry();
    fs.mkdirSync(OUT, { recursive: true });
    fs.writeFileSync(
        path.join(OUT, 'StakeRegistry.compiled.json'),
        JSON.stringify({ tolkVersion: result.tolkVersion, codeHashHex: result.codeHashHex, codeBoc64: result.codeBoc64 }, null, 2),
    );
    fs.writeFileSync(path.join(OUT, 'StakeRegistry.abi.json'), JSON.stringify(result.abiJson, null, 2));
    fs.writeFileSync(path.join(OUT, 'StakeRegistry.fif'), result.fiftCode);
    console.log(`tolk ${version}: StakeRegistry compiled, code hash ${result.codeHashHex}`);
    if (result.stderr) console.log(result.stderr);
}

if (require.main === module) {
    main().catch((e) => {
        console.error(e.message ?? e);
        process.exit(1);
    });
}
