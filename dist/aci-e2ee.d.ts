/**
 * Provider-neutral ACI E2EE v2 field encryption.
 *
 * The gateway receives only the encoded field ciphertext. Callers remain
 * responsible for verifying the ACI attestation and selecting the exact
 * quote-bound E2EE public key before calling these helpers.
 */
export declare const ACI_E2EE_VERSION = "2";
export declare const ACI_E2EE_ALGORITHM = "x25519-aes-256-gcm-hkdf-sha256";
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
/** Return the canonical additional-authenticated-data bytes for one ACI field. */
export declare function aciE2eeAad(context: AciE2eeContext): Uint8Array;
/** Generate the X25519 key pair used to decrypt fields returned to this client. */
export declare function createAciE2eeClientKeyPair(options?: AciE2eeKeyPairOptions): AciE2eeClientKeyPair;
/** Generate the 32-byte hexadecimal request nonce required by ACI E2EE v2. */
export declare function generateAciE2eeNonce(): string;
/** Encrypt one UTF-8 field for the quote-bound ACI E2EE public key. */
export declare function encryptAciE2eeField(plaintext: string, recipientPublicKeyHex: string, context: AciE2eeContext, options?: AciE2eeEncryptOptions): Promise<string>;
/** Decrypt and authenticate one ACI E2EE v2 response field. */
export declare function decryptAciE2eeField(ciphertextHex: string, recipientSecretKey: Uint8Array, context: AciE2eeContext): Promise<string>;
//# sourceMappingURL=aci-e2ee.d.ts.map