export declare function toHex(bytes: Uint8Array): string;
export declare function fromHex(hex: string): Uint8Array;
export declare function generateKeypair(): {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    pubKeyHex: string;
};
export declare function deriveAESKey(myPrivateKey: Uint8Array, theirPublicKeyHex: string): Promise<CryptoKey>;
export declare function encryptMessage(aesKey: CryptoKey, clientPubKeyBytes: Uint8Array, plaintext: string): Promise<string>;
export declare function decryptChunk(clientPrivateKey: Uint8Array, hexString: string): Promise<string>;
//# sourceMappingURL=crypto.d.ts.map