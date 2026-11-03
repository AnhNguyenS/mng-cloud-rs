/*
 * Browser adapter for the Rust/WASM E2EE engine.
 *
 * JavaScript never derives, stores or inspects library keys. It only passes
 * public metadata and ciphertext across the WASM boundary; the session object
 * owns the key in Rust memory and zeroizes it when released.
 */

import { trustedScriptUrl } from './trusted-types.js';

let enginePromise = null;

export function loadE2eeEngine(url = '/app/assets/wasm/mng_wasm.js') {
  if (!enginePromise) {
    enginePromise = (async () => {
      const module = await import(trustedScriptUrl(url));
      await module.default();
      return module;
    })().catch((error) => {
      enginePromise = null;
      throw error;
    });
  }
  return enginePromise;
}

/**
 * @param {object} params
 * @param {string} params.repoId
 * @param {string} params.password
 * @param {number} params.encVersion
 * @param {string} params.magicHex
 * @param {string} params.randomKeyHex
 * @param {string} [params.saltHex]
 * @returns {Promise<object>} WASM E2eeSession
 */
export async function openLibrary({
  repoId,
  password,
  encVersion,
  magicHex,
  randomKeyHex,
  saltHex = '',
}) {
  const engine = await loadE2eeEngine();
  return engine.E2eeSession.unlock(
    repoId,
    password,
    encVersion,
    magicHex,
    randomKeyHex,
    saltHex,
  );
}

export async function encryptBlock(session, plaintext) {
  return session.encryptBlock(plaintext);
}

export async function decryptBlock(session, ciphertext) {
  return session.decryptBlock(ciphertext);
}

export function releaseSession(session) {
  if (session && typeof session.free === 'function') session.free();
}
