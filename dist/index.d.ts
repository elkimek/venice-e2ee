import type { VeniceE2EEOptions, E2EESession, EncryptedPayload } from './types.js';
export declare function createVeniceE2EE(options: VeniceE2EEOptions): {
    createSession: (modelId: string) => Promise<E2EESession>;
    encrypt: (messages: Array<{
        role: string;
        content: string;
    }>, session: E2EESession) => Promise<EncryptedPayload>;
    decryptChunk: (hexChunk: string, session: E2EESession) => Promise<string>;
    decryptStream: (body: ReadableStream<Uint8Array>, session: E2EESession) => AsyncGenerator<string>;
    clearSession: () => void;
};
export declare function isE2EEModel(modelId: string): boolean;
export type { VeniceE2EEOptions, E2EESession, EncryptedPayload, DcapVerifier, DcapVerifyResult } from './types.js';
export type { AttestationResponse, AttestationResult, ServerVerification } from './attestation.js';
export { verifyAttestation, deriveEthAddress } from './attestation.js';
export { generateKeypair, deriveAESKey, encryptMessage, decryptChunk, toHex, fromHex, } from './crypto.js';
export { decryptSSEStream } from './stream.js';
//# sourceMappingURL=index.d.ts.map