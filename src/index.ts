import {
  generateKeypair,
  deriveAESKey,
  encryptMessage,
  decryptChunk,
  toHex,
} from './crypto.js';
import { decryptSSEStream } from './stream.js';
import type {
  VeniceE2EEOptions,
  E2EESession,
  EncryptedPayload,
} from './types.js';

const DEFAULT_BASE_URL = 'https://api.venice.ai';
const DEFAULT_SESSION_TTL = 30 * 60 * 1000; // 30 minutes

export function createVeniceE2EE(options: VeniceE2EEOptions) {
  const {
    apiKey,
    baseUrl = DEFAULT_BASE_URL,
    sessionTTL = DEFAULT_SESSION_TTL,
  } = options;
  let _session: E2EESession | null = null;

  async function fetchModelPublicKey(modelId: string): Promise<string> {
    const nonce = toHex(crypto.getRandomValues(new Uint8Array(32)));
    const url = `${baseUrl}/api/v1/tee/attestation?model=${encodeURIComponent(modelId)}&nonce=${nonce}`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    if (!res.ok) throw new Error(`TEE attestation failed (${res.status})`);
    const data = await res.json();
    const pubKey =
      data.signing_public_key || data.signing_key || data.public_key;
    if (!pubKey) throw new Error('No public key in attestation response');
    return pubKey;
  }

  async function createSession(modelId: string): Promise<E2EESession> {
    if (
      _session &&
      _session.modelId === modelId &&
      Date.now() - _session.created < sessionTTL
    ) {
      return _session;
    }

    const keypair = generateKeypair();
    const modelPubKeyHex = await fetchModelPublicKey(modelId);
    const aesKey = await deriveAESKey(keypair.privateKey, modelPubKeyHex);

    _session = {
      ...keypair,
      modelPubKeyHex,
      aesKey,
      modelId,
      created: Date.now(),
    };

    return _session;
  }

  async function encrypt(
    messages: Array<{ role: string; content: string }>,
    session: E2EESession
  ): Promise<EncryptedPayload> {
    const encryptedMessages = await Promise.all(
      messages.map(async (msg) => ({
        role: msg.role,
        content: await encryptMessage(
          session.aesKey,
          session.publicKey,
          msg.content
        ),
      }))
    );

    return {
      encryptedMessages,
      headers: {
        'X-Venice-TEE-Client-Pub-Key': session.pubKeyHex,
        'X-Venice-TEE-Model-Pub-Key': session.modelPubKeyHex,
        'X-Venice-TEE-Signing-Algo': 'ecdsa',
      },
      veniceParameters: { enable_e2ee: true as const },
    };
  }

  async function decrypt(
    hexChunk: string,
    session: E2EESession
  ): Promise<string> {
    return decryptChunk(session.privateKey, hexChunk);
  }

  async function* decryptStream(
    body: ReadableStream<Uint8Array>,
    session: E2EESession
  ): AsyncGenerator<string> {
    yield* decryptSSEStream(body, session.privateKey);
  }

  function clearSession(): void {
    _session = null;
  }

  return {
    createSession,
    encrypt,
    decryptChunk: decrypt,
    decryptStream,
    clearSession,
  };
}

export function isE2EEModel(modelId: string): boolean {
  return modelId.startsWith('e2ee-');
}

export type { VeniceE2EEOptions, E2EESession, EncryptedPayload } from './types.js';
export {
  generateKeypair,
  deriveAESKey,
  encryptMessage,
  decryptChunk,
  toHex,
  fromHex,
} from './crypto.js';
export { decryptSSEStream } from './stream.js';
