import { getPublicKey, getSharedSecret, utils } from '@noble/secp256k1';

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export function generateKeypair(): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  pubKeyHex: string;
} {
  const privateKey = utils.randomPrivateKey();
  const publicKey = getPublicKey(privateKey, false); // uncompressed = 65 bytes
  const pubKeyHex = toHex(publicKey);
  return { privateKey, publicKey, pubKeyHex };
}

export async function deriveAESKey(
  myPrivateKey: Uint8Array,
  theirPublicKeyHex: string
): Promise<CryptoKey> {
  const sharedPoint = getSharedSecret(myPrivateKey, theirPublicKeyHex, false);
  const xCoord = sharedPoint.slice(1, 33); // 32-byte x-coordinate
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    xCoord,
    'HKDF',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode('ecdsa_encryption'),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptMessage(
  aesKey: CryptoKey,
  clientPubKeyBytes: Uint8Array,
  plaintext: string
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(plaintext)
  );
  const out = new Uint8Array(65 + 12 + ct.byteLength);
  out.set(clientPubKeyBytes, 0);
  out.set(iv, 65);
  out.set(new Uint8Array(ct), 77);
  return toHex(out);
}

export async function decryptChunk(
  clientPrivateKey: Uint8Array,
  hexString: string
): Promise<string> {
  // Short or non-hex content is plaintext passthrough (e.g. whitespace tokens)
  if (
    !hexString ||
    hexString.length < 154 ||
    !/^[0-9a-f]+$/i.test(hexString)
  ) {
    return hexString;
  }
  const raw = fromHex(hexString);
  const serverEphemeralPubKey = toHex(raw.slice(0, 65));
  const iv = raw.slice(65, 77);
  const ciphertext = raw.slice(77);
  const chunkKey = await deriveAESKey(clientPrivateKey, serverEphemeralPubKey);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    chunkKey,
    ciphertext
  );
  return new TextDecoder().decode(pt);
}
