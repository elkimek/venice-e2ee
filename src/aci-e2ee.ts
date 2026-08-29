/**
 * Provider-neutral ACI E2EE v2 field encryption.
 *
 * The gateway receives only the encoded field ciphertext. Callers remain
 * responsible for verifying the ACI attestation and selecting the exact
 * quote-bound E2EE public key before calling these helpers.
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { fromHex, toHex } from './crypto.js';
import { jcsStringify } from './receipt.js';

export const ACI_E2EE_VERSION = '2';
export const ACI_E2EE_ALGORITHM = 'x25519-aes-256-gcm-hkdf-sha256';

const HKDF_INFO = new TextEncoder().encode('aci.e2ee.v2.x25519');
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const NONCE_PATTERN = /^[0-9a-f]{64}$/i;
const HEX_PATTERN = /^(?:[0-9a-f]{2})+$/i;

export interface AciE2eeContext {
  purpose: 'aci.e2ee.request.v2' | 'aci.e2ee.response.v2';
  model: string;
  field: string;
  nonce: string;
  timestamp: number;
  responseId?: string;
}

export interface AciE2eeClientKeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyHex: string;
}

export interface AciE2eeKeyPairOptions {
  secretKey?: Uint8Array;
}

export interface AciE2eeEncryptOptions {
  ephemeralSecretKey?: Uint8Array;
  aesNonce?: Uint8Array;
}

function secureRandomBytes(length: number): Uint8Array {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error('ACI E2EE needs a secure cryptographic runtime');
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(arrays.reduce((total, value) => total + value.length, 0));
  let offset = 0;
  for (const value of arrays) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

function decodeHex(value: string, label: string): Uint8Array {
  const clean = value.replace(/^0x/i, '');
  if (!HEX_PATTERN.test(clean)) throw new Error(`${label} must be hexadecimal bytes`);
  return fromHex(clean);
}

function validateContext(context: AciE2eeContext): void {
  const request = context?.purpose === 'aci.e2ee.request.v2';
  const response = context?.purpose === 'aci.e2ee.response.v2';
  if (!request && !response) throw new Error('Unsupported ACI E2EE field purpose');
  if (typeof context.model !== 'string' || !context.model || context.model.length > 256) {
    throw new Error('ACI E2EE context needs a bounded model identifier');
  }
  if (typeof context.field !== 'string' || !context.field || context.field.length > 512) {
    throw new Error('ACI E2EE context needs a bounded field identifier');
  }
  if (!NONCE_PATTERN.test(context.nonce)) {
    throw new Error('ACI E2EE context nonce must contain exactly 32 hexadecimal bytes');
  }
  if (!Number.isSafeInteger(context.timestamp) || context.timestamp <= 0) {
    throw new Error('ACI E2EE context needs a positive integer timestamp');
  }
  if (request && context.responseId !== undefined) {
    throw new Error('ACI E2EE request context must not contain a response id');
  }
  if (response && (typeof context.responseId !== 'string'
      || !context.responseId || context.responseId.length > 256)) {
    throw new Error('ACI E2EE response context needs a bounded response id');
  }
}

async function deriveAesKey(sharedSecret: Uint8Array): Promise<CryptoKey> {
  const keyBytes = hkdf(sha256, sharedSecret, undefined, HKDF_INFO, 32);
  try {
    return await globalThis.crypto.subtle.importKey(
      'raw',
      keyBytes as BufferSource,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
  } finally {
    keyBytes.fill(0);
  }
}

/** Return the canonical additional-authenticated-data bytes for one ACI field. */
export function aciE2eeAad(context: AciE2eeContext): Uint8Array {
  validateContext(context);
  return encoder.encode(
    jcsStringify({
      purpose: context.purpose,
      algo: ACI_E2EE_ALGORITHM,
      model: context.model,
      ...(context.responseId === undefined ? {} : { id: context.responseId }),
      field: context.field,
      nonce: context.nonce,
      ts: context.timestamp,
    })
  );
}

/** Generate the X25519 key pair used to decrypt fields returned to this client. */
export function createAciE2eeClientKeyPair(
  options: AciE2eeKeyPairOptions = {}
): AciE2eeClientKeyPair {
  const secretKey = options.secretKey
    ? Uint8Array.from(options.secretKey)
    : secureRandomBytes(32);
  if (secretKey.length !== 32) {
    secretKey.fill(0);
    throw new Error('ACI E2EE client secret must contain exactly 32 bytes');
  }
  try {
    const publicKey = x25519.getPublicKey(secretKey);
    return { secretKey, publicKey, publicKeyHex: toHex(publicKey) };
  } catch (error) {
    secretKey.fill(0);
    throw error;
  }
}

/** Generate the 32-byte hexadecimal request nonce required by ACI E2EE v2. */
export function generateAciE2eeNonce(): string {
  return toHex(secureRandomBytes(32));
}

/** Encrypt one UTF-8 field for the quote-bound ACI E2EE public key. */
export async function encryptAciE2eeField(
  plaintext: string,
  recipientPublicKeyHex: string,
  context: AciE2eeContext,
  options: AciE2eeEncryptOptions = {}
): Promise<string> {
  if (typeof plaintext !== 'string') throw new TypeError('ACI E2EE plaintext must be a string');
  validateContext(context);
  const recipient = decodeHex(recipientPublicKeyHex, 'ACI E2EE recipient key');
  if (recipient.length !== 32) {
    throw new Error('ACI E2EE recipient key must contain exactly 32 bytes');
  }
  const ephemeralSecret = options.ephemeralSecretKey
    ? Uint8Array.from(options.ephemeralSecretKey)
    : secureRandomBytes(32);
  const nonce = options.aesNonce
    ? Uint8Array.from(options.aesNonce)
    : secureRandomBytes(12);
  if (ephemeralSecret.length !== 32 || nonce.length !== 12) {
    ephemeralSecret.fill(0);
    throw new Error('Invalid ACI E2EE encryption parameters');
  }

  let shared: Uint8Array | undefined;
  try {
    const ephemeralPublic = x25519.getPublicKey(ephemeralSecret);
    shared = x25519.getSharedSecret(ephemeralSecret, recipient);
    const key = await deriveAesKey(shared);
    const ciphertext = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: nonce as BufferSource,
          additionalData: aciE2eeAad(context) as BufferSource,
          tagLength: 128,
        },
        key,
        encoder.encode(plaintext) as BufferSource
      )
    );
    return toHex(concatBytes(ephemeralPublic, nonce, ciphertext));
  } finally {
    ephemeralSecret.fill(0);
    shared?.fill(0);
  }
}

/** Decrypt and authenticate one ACI E2EE v2 response field. */
export async function decryptAciE2eeField(
  ciphertextHex: string,
  recipientSecretKey: Uint8Array,
  context: AciE2eeContext
): Promise<string> {
  validateContext(context);
  const bytes = decodeHex(ciphertextHex, 'ACI E2EE response field');
  const secret = Uint8Array.from(recipientSecretKey);
  if (bytes.length < 61 || secret.length !== 32) {
    secret.fill(0);
    throw new Error('ACI E2EE response field is malformed');
  }

  let shared: Uint8Array | undefined;
  try {
    shared = x25519.getSharedSecret(secret, bytes.slice(0, 32));
    const key = await deriveAesKey(shared);
    const plaintext = await globalThis.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: bytes.slice(32, 44) as BufferSource,
        additionalData: aciE2eeAad(context) as BufferSource,
        tagLength: 128,
      },
      key,
      bytes.slice(44) as BufferSource
    );
    return decoder.decode(plaintext);
  } catch {
    throw new Error('ACI E2EE response authentication failed');
  } finally {
    secret.fill(0);
    shared?.fill(0);
  }
}
