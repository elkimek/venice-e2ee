import { describe, it, expect } from 'vitest';
import {
  generateKeypair,
  deriveAESKey,
  encryptMessage,
  decryptChunk,
  toHex,
  fromHex,
} from './crypto.js';

describe('hex utilities', () => {
  it('roundtrips bytes through hex', () => {
    const bytes = new Uint8Array([0, 1, 127, 128, 255]);
    expect(fromHex(toHex(bytes))).toEqual(bytes);
  });

  it('handles empty input', () => {
    expect(toHex(new Uint8Array(0))).toBe('');
    expect(fromHex('')).toEqual(new Uint8Array(0));
  });
});

describe('key generation', () => {
  it('generates valid secp256k1 keypair', () => {
    const kp = generateKeypair();
    expect(kp.privateKey).toBeInstanceOf(Uint8Array);
    expect(kp.privateKey.length).toBe(32);
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey.length).toBe(65); // uncompressed
    expect(kp.publicKey[0]).toBe(0x04); // uncompressed prefix
    expect(kp.pubKeyHex).toHaveLength(130); // 65 bytes * 2 hex chars
  });

  it('generates unique keypairs', () => {
    const a = generateKeypair();
    const b = generateKeypair();
    expect(a.pubKeyHex).not.toBe(b.pubKeyHex);
  });
});

describe('AES key derivation', () => {
  it('derives identical keys from both sides of ECDH', async () => {
    const alice = generateKeypair();
    const bob = generateKeypair();

    // Alice derives key using Bob's public key
    const aliceKey = await deriveAESKey(alice.privateKey, bob.pubKeyHex);
    // Bob derives key using Alice's public key
    const bobKey = await deriveAESKey(bob.privateKey, alice.pubKeyHex);

    // Both should produce working encrypt/decrypt — verify by encrypting
    // with one and decrypting with the other
    const plaintext = 'ECDH symmetry test';
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aliceKey,
      new TextEncoder().encode(plaintext)
    );
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      bobKey,
      ct
    );
    expect(new TextDecoder().decode(pt)).toBe(plaintext);
  });
});

describe('encrypt/decrypt roundtrip', () => {
  it('client encrypts, server decrypts', async () => {
    const client = generateKeypair();
    const server = generateKeypair();

    // Client derives AES key with server's public key
    const clientAES = await deriveAESKey(client.privateKey, server.pubKeyHex);

    // Client encrypts message
    const plaintext = 'Hello, Venice TEE!';
    const cipherHex = await encryptMessage(
      clientAES,
      client.publicKey,
      plaintext
    );

    // Ciphertext format: hex(pubKey65 + nonce12 + ciphertext)
    expect(cipherHex.length).toBeGreaterThan(154); // (65+12)*2 = 154 min

    // Server decrypts — decryptChunk extracts embedded client pubkey,
    // does ECDH(server_priv, client_pub) which equals ECDH(client_priv, server_pub)
    const decrypted = await decryptChunk(server.privateKey, cipherHex);
    expect(decrypted).toBe(plaintext);
  });

  it('server response chunks (per-chunk ephemeral keys)', async () => {
    const client = generateKeypair();

    // Server generates ephemeral keypair per response chunk
    const serverEphemeral = generateKeypair();

    // Server derives AES key using (server_ephemeral_priv, client_pub)
    const serverAES = await deriveAESKey(
      serverEphemeral.privateKey,
      client.pubKeyHex
    );

    // Server encrypts response chunk
    const responseText = 'The answer is 42.';
    const responseCipherHex = await encryptMessage(
      serverAES,
      serverEphemeral.publicKey,
      responseText
    );

    // Client decrypts using their private key
    const decrypted = await decryptChunk(client.privateKey, responseCipherHex);
    expect(decrypted).toBe(responseText);
  });

  it('handles multiple chunks with different ephemeral keys', async () => {
    const client = generateKeypair();
    const chunks = ['chunk one', 'chunk two', 'chunk three'];

    for (const chunk of chunks) {
      // Each chunk gets a fresh server ephemeral keypair
      const serverEphemeral = generateKeypair();
      const serverAES = await deriveAESKey(
        serverEphemeral.privateKey,
        client.pubKeyHex
      );
      const cipherHex = await encryptMessage(
        serverAES,
        serverEphemeral.publicKey,
        chunk
      );
      const decrypted = await decryptChunk(client.privateKey, cipherHex);
      expect(decrypted).toBe(chunk);
    }
  });
});

describe('decryptChunk passthrough', () => {
  it('passes through empty string', async () => {
    const kp = generateKeypair();
    expect(await decryptChunk(kp.privateKey, '')).toBe('');
  });

  it('passes through short strings', async () => {
    const kp = generateKeypair();
    expect(await decryptChunk(kp.privateKey, 'hello')).toBe('hello');
  });

  it('passes through whitespace', async () => {
    const kp = generateKeypair();
    expect(await decryptChunk(kp.privateKey, '   ')).toBe('   ');
  });

  it('passes through non-hex strings', async () => {
    const kp = generateKeypair();
    expect(await decryptChunk(kp.privateKey, 'not-hex-data!')).toBe(
      'not-hex-data!'
    );
  });
});
