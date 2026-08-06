import { type ContentPart } from './tools.js';
import type { SignatureResponse } from './receipt.js';
import { type AttestationResponse } from './attestation.js';
import type { VeniceE2EEOptions, E2EESession, EncryptedPayload } from './types.js';
export declare function createVeniceE2EE(options: VeniceE2EEOptions): {
    createSession: (modelId: string) => Promise<E2EESession>;
    attest: (modelId: string) => Promise<AttestationResponse>;
    encrypt: (messages: Array<{
        role: string;
        content?: string | ContentPart[] | null;
        tool_call_id?: string;
        [key: string]: unknown;
    }>, session: E2EESession) => Promise<EncryptedPayload>;
    decryptChunk: (hexChunk: string, session: E2EESession) => Promise<string>;
    decryptStream: (body: ReadableStream<Uint8Array>, session: E2EESession) => AsyncGenerator<string>;
    fetchResponseSignature: (modelId: string, requestId: string) => Promise<SignatureResponse>;
    clearSession: () => void;
};
export declare function isE2EEModel(modelId: string): boolean;
export type { VeniceE2EEOptions, E2EESession, EncryptedPayload, DcapVerifier, DcapVerifyResult, ExpectedTdxMeasurements, TdxMeasurements, } from './types.js';
export type { AttestationResponse, AttestationResult, AttestationVerificationOptions, ServerVerification, } from './attestation.js';
export { verifyAttestation, deriveEthAddress } from './attestation.js';
export { verifyReceipt, receiptSigningBytes, recoverReceiptSigner, jcsStringify, sha256Prefixed, BODY_BINDING_CHECKS, hashReceiptBody, computeWorkloadId, computeWorkloadKeysetDigest, } from './receipt.js';
export { ACI_ATTESTATION_PATH, ACI_KEYSET_ENDORSEMENT_PURPOSE, ACI_REPORT_DATA_PURPOSE, aciKeysetEndorsementPayload, aciReportData, aciReportDataStatement, establishAciTrustAnchor, fetchAciAttestation, generateAciNonce, verifyAciAttestation, } from './aci.js';
export type { AciAttestationReport, AciAttestationResult, AciCheck, AciKeysetEndorsement, VerifyAciAttestationOptions, } from './aci.js';
export type { Receipt, ReceiptEvent, ReceiptCheck, ReceiptVerification, SignatureResponse, WorkloadKeyset, WorkloadIdentity, WorkloadPublicKey, KeysetKey, ReceiptTrustAnchor, ReceiptBody, ReceiptResponseHashField, VerifyReceiptOptions, } from './receipt.js';
export { generateKeypair, deriveAESKey, encryptMessage, decryptChunk, toHex, fromHex, } from './crypto.js';
export { decryptSSEStream } from './stream.js';
export { buildToolSystemPrompt, renderToolMessages, parseToolCalls, generateToolCallId, flattenMessageContent, ToolCallStreamParser, TOOL_CALL_OPEN, TOOL_CALL_CLOSE, TOOL_RESPONSE_OPEN, TOOL_RESPONSE_CLOSE, } from './tools.js';
export type { ToolDefinition, ToolFunctionDefinition, ToolCall, ToolChoice, ToolChatMessage, ContentPart, ParseResult, ToolParserOptions, } from './tools.js';
//# sourceMappingURL=index.d.ts.map