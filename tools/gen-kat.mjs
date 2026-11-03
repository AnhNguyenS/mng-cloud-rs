// Generate deterministic Seafile E2EE v2/v3 vectors with the exact same
// WebCrypto algorithm used by the deployed browser code.
//
// Usage: node tools/gen-kat.mjs [output.json]

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { webcrypto } from 'node:crypto';

const { subtle } = webcrypto;
const text = new TextEncoder();

const password = 'correct horse battery staple';
const repoId = '8f1c0d3e-2a4b-4c5d-9e6f-0123456789ab';
const fixedSalt = Uint8Array.from([0xda, 0x90, 0x45, 0xc3, 0x06, 0xc7, 0xcc, 0x26]);
const saltV3 = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
const secret = Uint8Array.from({ length: 32 }, (_, i) => i);
const plain = text.encode('The quick brown fox jumps over the lazy dog. 0123456789 ABCDEFGH');

const toHex = (bytes) => Buffer.from(bytes).toString('hex');
const fromHex = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));

async function pbkdf2(data, salt, iterations, bytes = 32) {
  const material = await subtle.importKey('raw', data, 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    bytes * 8,
  ));
}

async function aesKey(raw, usages) {
  return subtle.importKey('raw', raw, { name: 'AES-CBC' }, false, usages);
}

async function encryptBlock(rawKey, iv, data) {
  const key = await aesKey(rawKey, ['encrypt']);
  return new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, key, data));
}

async function sha1Hex(data) {
  return toHex(new Uint8Array(await subtle.digest('SHA-1', data)));
}

async function derive(repoId, password, salt) {
  const pass = text.encode(password);
  const key = await pbkdf2(pass, salt, 1000, 32);
  const magic = await pbkdf2(new Uint8Array([...text.encode(repoId), ...pass]), salt, 1000, 32);
  const keyIv = await pbkdf2(key, salt, 10, 16);
  const randomKey = await encryptBlock(key, keyIv, secret);
  const contentKey = await pbkdf2(secret, salt, 1000, 32);
  const contentIv = await pbkdf2(contentKey, salt, 10, 16);
  return { key, magic, keyIv, randomKey, contentKey, contentIv };
}

const v2 = await derive(repoId, password, fixedSalt);
const cipher = await encryptBlock(v2.contentKey, v2.contentIv, plain);
const emptyCipher = await encryptBlock(v2.contentKey, v2.contentIv, new Uint8Array());

const v3 = await derive(repoId, password, saltV3);
const cipherV3 = await encryptBlock(v3.contentKey, v3.contentIv, plain);

const fixture = {
  description: 'Deterministic Seafile E2EE vectors generated with WebCrypto',
  password,
  repo_id: repoId,
  salt_v2_hex: toHex(fixedSalt),
  salt_v3_hex: toHex(saltV3),
  magic_hex: toHex(v2.magic),
  random_key_hex: toHex(v2.randomKey),
  content_key_hex: toHex(v2.contentKey),
  content_iv_hex: toHex(v2.contentIv),
  plain_hex: toHex(plain),
  cipher_hex: toHex(cipher),
  block_id: await sha1Hex(cipher),
  empty_cipher_hex: toHex(emptyCipher),
  empty_block_id: await sha1Hex(emptyCipher),
  v3: {
    magic_hex: toHex(v3.magic),
    random_key_hex: toHex(v3.randomKey),
    content_key_hex: toHex(v3.contentKey),
    content_iv_hex: toHex(v3.contentIv),
    cipher_hex: toHex(cipherV3),
    block_id: await sha1Hex(cipherV3),
  },
};

const out = process.argv[2] || 'crates/mng-core/tests/fixtures/e2ee_kat.json';
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');
console.log(`wrote ${out}`);
console.log(`v2 magic=${fixture.magic_hex}`);
console.log(`v2 block=${fixture.block_id}`);
