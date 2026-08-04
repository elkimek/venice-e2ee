/**
 * Verification of Venice's `/api/v1/tee/signature` response receipts.
 *
 * A receipt is useful only when three independent bindings hold:
 *
 * 1. its signing key belongs to a workload keyset the caller already trusts;
 * 2. it names the completion the caller made; and
 * 3. its request/response hashes match the bytes the caller intended to send
 *    and accept.
 *
 * Venice's legacy `/api/v1/tee/attestation` quote binds an E2EE key and nonce,
 * not the ACI workload-keyset digest. Consequently this module never promotes
 * self-described values from that response into a trust root. The caller must
 * supply a trust anchor established from canonical ACI attestation verification
 * or an independently pinned workload identity and keyset digest.
 *
 * Binding (3) is unreachable for a client of `api.venice.ai`. Measured on the
 * E2EE and TEE-only paths, streaming and not, with the exact bytes sent and
 * received: both body hashes fail in all four combinations, which places a
 * re-serializing hop between the caller and the enclave that issues the receipt.
 * The requirement stays — `verified` is false without it, and this module does
 * not get to decide the binding is optional — but callers behind such a gateway
 * should distinguish that from a receipt that failed for any other reason. See
 * {@link BODY_BINDING_CHECKS}.
 */
import type { AttestationResponse } from './attestation.js';
export interface WorkloadPublicKey {
    algo: string;
    public_key: string;
    [key: string]: unknown;
}
export interface WorkloadIdentity {
    public_key: WorkloadPublicKey;
    subject?: string | null;
    [key: string]: unknown;
}
/** A key entry inside a workload keyset. */
export interface KeysetKey {
    key_id: string;
    algo: string;
    public_key: string;
    [key: string]: unknown;
}
export interface WorkloadKeyset {
    workload_identity: WorkloadIdentity;
    receipt_signing_keys: KeysetKey[];
    [key: string]: unknown;
}
export interface ReceiptSignature {
    algo: string;
    key_id: string;
    value: string;
}
export interface ReceiptEvent {
    seq: number;
    type: string;
    body_hash?: string;
    wire_hash?: string;
    cleartext_hash?: string;
    [key: string]: unknown;
}
export interface Receipt {
    api_version: string;
    receipt_id: string;
    chat_id: string;
    workload_id: string;
    workload_keyset_digest: string;
    event_log: ReceiptEvent[];
    signature: ReceiptSignature;
    [key: string]: unknown;
}
/** The body of `GET /api/v1/tee/signature`. */
export interface SignatureResponse {
    api_version?: string;
    text?: string;
    signature?: string;
    signing_address?: string;
    receipt: Receipt;
    [key: string]: unknown;
}
export interface ReceiptCheck {
    name: string;
    ok: boolean;
    detail?: string;
}
export interface ReceiptVerification {
    /** True only when every required trust, signature, identity, and body check passed. */
    verified: boolean;
    checks: ReceiptCheck[];
}
/** Values established by canonical quote verification or pinned independently. */
export interface ReceiptTrustAnchor {
    workloadId: string;
    workloadKeysetDigest: string;
}
/**
 * The check names that bind a receipt to specific request and response bytes.
 *
 * Exported so a caller can tell "this binding is not reachable from here" apart
 * from "this receipt is wrong" without matching on string literals. A caller
 * behind a re-serializing gateway will see exactly these two fail on every
 * completion; anything else failing alongside them is a real problem.
 */
export declare const BODY_BINDING_CHECKS: readonly string[];
export type ReceiptBody = string | Uint8Array;
export type ReceiptResponseHashField = 'wire_hash' | 'cleartext_hash';
export interface VerifyReceiptOptions {
    /** Independently established identity and keyset digest. Never copy unverified report fields. */
    trustAnchor: ReceiptTrustAnchor;
    /** Venice completion id the receipt must name. */
    requestId: string;
    /** Exact request bytes whose hash must match `request.received.body_hash`. */
    requestBody: ReceiptBody;
    /** Exact response bytes whose hash must match the explicitly selected receipt field. */
    responseBody: ReceiptBody;
    /** Select the response representation the caller supplies. Required to avoid ambiguity. */
    responseHashField: ReceiptResponseHashField;
}
type JsonValue = null | boolean | number | string | JsonValue[] | {
    [key: string]: JsonValue | undefined;
};
/** RFC 8785 JSON Canonicalization Scheme for the JSON subset ACI uses. */
export declare function jcsStringify(value: JsonValue): string;
/** `sha256:<hex>` over the UTF-8 bytes of `text`. */
export declare function sha256Prefixed(text: string): string;
/** `sha256:<hex>` over exact body bytes. Strings are encoded as UTF-8. */
export declare function hashReceiptBody(body: ReceiptBody): string;
/** ACI workload id: SHA-256 of the JCS identity public-key object. */
export declare function computeWorkloadId(publicKey: WorkloadPublicKey): string;
/** ACI workload-keyset digest: SHA-256 of the whole JCS keyset. */
export declare function computeWorkloadKeysetDigest(keyset: WorkloadKeyset): string;
/** The exact bytes the receipt signature covers: JCS minus `signature.value`. */
export declare function receiptSigningBytes(receipt: Receipt): Uint8Array;
/**
 * Verify a receipt against an independently established workload trust anchor.
 *
 * Every required check is reported rather than thrown. Missing options, trust
 * material, events, or hashes fail closed at runtime even for untyped callers.
 */
export declare function verifyReceipt(signatureResponse: SignatureResponse, attestation: AttestationResponse, options: VerifyReceiptOptions): Promise<ReceiptVerification>;
export {};
//# sourceMappingURL=receipt.d.ts.map