// End-to-end check of the generated WebAssembly boundary.
//
// Build first:
//   cargo build -p mng-wasm --release --target wasm32-unknown-unknown
//   wasm-bindgen --target nodejs --out-dir dist/wasm-node \
//     target/wasm32-unknown-unknown/release/mng_wasm.wasm
//   node tools/test-wasm.mjs

import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const wasm = require('../dist/wasm-node/mng_wasm.js');

const fixture = JSON.parse(
  readFileSync(new URL('../crates/mng-core/tests/fixtures/e2ee_kat.json', import.meta.url)),
);
const toHex = (bytes) => Buffer.from(bytes).toString('hex');
const fromHex = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const v2 = wasm.E2eeSession.unlock(
  fixture.repo_id,
  fixture.password,
  2,
  fixture.magic_hex,
  fixture.random_key_hex,
  '',
);
assert(toHex(v2.encryptBlock(fromHex(fixture.plain_hex))) === fixture.cipher_hex, 'v2 cipher mismatch');
assert(toHex(v2.decryptBlock(fromHex(fixture.cipher_hex))) === fixture.plain_hex, 'v2 plaintext mismatch');
assert(wasm.blockId(fromHex(fixture.cipher_hex)) === fixture.block_id, 'v2 block id mismatch');
v2.free();

const v3 = wasm.E2eeSession.unlock(
  fixture.repo_id,
  fixture.password,
  3,
  fixture.v3.magic_hex,
  fixture.v3.random_key_hex,
  fixture.salt_v3_hex,
);
assert(toHex(v3.encryptBlock(fromHex(fixture.plain_hex))) === fixture.v3.cipher_hex, 'v3 cipher mismatch');
v3.free();

let rejected = false;
try {
  wasm.E2eeSession.unlock(
    fixture.repo_id,
    fixture.password,
    2,
    fixture.v3.magic_hex,
    fixture.random_key_hex,
    '',
  );
} catch (error) {
  rejected = true;
}
assert(rejected, 'wrong password was not rejected');

console.log(`wasm ok: v2 block=${fixture.block_id} v3 block=${fixture.v3.block_id}`);
