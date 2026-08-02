/**
 * Verification of Venice's `/api/v1/tee/signature` response receipts.
 *
 * Attestation proves an enclave exists. It says nothing about whether *your*
 * request went through it — Venice could serve you from an ordinary GPU and the
 * attestation would still check out. The receipt closes that gap: it names your
 * completion, records what the gateway did with it, and is signed by a key that
 * only lives inside the attested workload.
 *
 * The scheme is Phala's Attested Confidential Inference (`aci/1`), implemented
 * by the Dstack-TEE/private-ai-gateway reference verifier: the receipt carries
 * an Ed25519 signature over the RFC 8785 (JCS) canonicalization of itself with
 * `signature.value` removed, under a key drawn from the attested keyset.
 *
 * Note the signature that is *not* used here. The signature response also has a
 * top-level secp256k1 `signature` over a `<request-hash>:<response-hash>` text;
 * its message construction is undocumented and is not what the reference
 * verifier checks.
 */
import type { AttestationResponse } from './attestation.js';
/** A key entry inside the attested workload keyset. */
export interface KeysetKey {
    key_id: string;
    algo: string;
    public_key: string;
    [key: string]: unknown;
}
export interface WorkloadKeyset {
    receipt_signing_keys?: KeysetKey[];
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
    cleartext_hash?: string;
    [key: string]: unknown;
}
export interface Receipt {
    receipt_id: string;
    chat_id: string;
    workload_keyset_digest: string;
    event_log: ReceiptEvent[];
    signature: ReceiptSignature;
    [key: string]: unknown;
}
/** The body of `GET /api/v1/tee/signature`. */
export interface SignatureResponse {
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
    /** True only when every check that ran passed. */
    verified: boolean;
    checks: ReceiptCheck[];
}
export interface VerifyReceiptOptions {
    /** Completion id the receipt must name, if you want that bound too. */
    requestId?: string;
}
type JsonValue = null | boolean | number | string | JsonValue[] | {
    [key: string]: JsonValue;
};
/**
 * RFC 8785 JSON Canonicalization Scheme.
 *
 * Object keys sort by UTF-16 code unit, which is what `Array.prototype.sort`
 * does by default, and no insignificant whitespace survives. `undefined`
 * properties are dropped the way `JSON.stringify` drops them.
 */
export declare function jcsStringify(value: JsonValue): string;
/** `sha256:<hex>` over the UTF-8 bytes of `text`, the form ACI digests take. */
export declare function sha256Prefixed(text: string): string;
/** The exact bytes the receipt signature covers: JCS of the receipt, minus the signature value. */
export declare function receiptSigningBytes(receipt: Receipt): Uint8Array;
/**
 * Verify a signature response against the attestation it should chain to.
 *
 * Every check is reported rather than thrown, so a caller can log a partial
 * result instead of losing the detail in an exception. `verified` is true only
 * when all of them pass.
 */
export declare function verifyReceipt(signatureResponse: SignatureResponse, attestation: AttestationResponse, options?: VerifyReceiptOptions): Promise<ReceiptVerification>;
export {};
//# sourceMappingURL=receipt.d.ts.map