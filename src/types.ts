export interface VeniceE2EEOptions {
  apiKey: string;
  baseUrl?: string;
  sessionTTL?: number;
}

export interface E2EESession {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  pubKeyHex: string;
  modelPubKeyHex: string;
  aesKey: CryptoKey;
  modelId: string;
  created: number;
}

export interface EncryptedPayload {
  encryptedMessages: Array<{ role: string; content: string }>;
  headers: Record<string, string>;
  veniceParameters: { enable_e2ee: true };
}
