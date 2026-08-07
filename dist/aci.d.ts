/**
 * ACI attestation reports — the receipt trust anchor, proven instead of pinned.
 *
 * {@link verifyReceipt} needs a workload identity and keyset digest it can
 * trust, and refuses to lift them out of the response being checked. Venice's
 * `/api/v1/tee/attestation` cannot supply them: it serves the legacy report
 * shape, whose `report_data` is `[address(20) | zeros(12) | nonce(32)]`. That
 * binds the E2EE signing key and the nonce, and says nothing about the keyset.
 * Hence the trust-on-first-use pinning callers have had to fall back on.
 *
 * The same enclave also speaks the native ACI protocol, and there the quote
 * says considerably more. `report_data` is
 *
 * ```text
 * sha256(JCS({
 *   purpose: "aci.report_data.v1",
 *   workload_id, workload_keyset_digest, nonce
 * }))
 * ```
 *
 * so a verified quote commits to the keyset digest directly. Recompute that
 * statement, check it against the quote's REPORTDATA, and the anchor is
 * established by Intel's root of trust rather than by having seen it before.
 *
 * The endpoint is unauthenticated and lives on the gateway's own hostnames
 * (`tee.redpill.ai`, `inference.phala.com`, `api.redpill.ai`), not behind
 * `api.venice.ai`. Which host served it does not matter: the quote is
 * self-authenticating, and the digest it binds is compared against the one
 * Venice reports. If they agree, the keyset Venice is serving is the keyset the
 * quote covers.
 */
import { type ReceiptTrustAnchor, type WorkloadKeyset } from './receipt.js';
import type { DcapVerifier, DcapVerifyResult, ExpectedTdxMeasurements, TdxMeasurements } from './types.js';
/** Purpose tag in the statement the quote's `report_data` covers (ACI §4). */
export declare const ACI_REPORT_DATA_PURPOSE = "aci.report_data.v1";
/** Purpose tag in the payload the workload identity key endorses (ACI §4.2). */
export declare const ACI_KEYSET_ENDORSEMENT_PURPOSE = "aci.keyset.endorsement.v1";
/** Path of the unauthenticated native ACI attestation endpoint. */
export declare const ACI_ATTESTATION_PATH = "/v1/aci/attestation";
export interface AciKeysetEndorsement {
    algo: string;
    value: string;
}
export interface AciAttestationReport {
    api_version?: string;
    workload_id?: string;
    workload_keyset_digest?: string;
    attestation?: {
        vendor?: string;
        tee_type?: string;
        workload_keyset?: WorkloadKeyset;
        report_data?: string;
        keyset_endorsement?: AciKeysetEndorsement;
        source_provenance?: {
            repo_url?: string;
            repo_commit?: string;
            image_digest?: string | null;
        };
        freshness?: {
            fetched_at?: number;
            stale_after?: number;
        };
        evidence?: {
            quote?: string;
            [key: string]: unknown;
        };
        [key: string]: unknown;
    };
    [key: string]: unknown;
}
export interface AciCheck {
    name: string;
    ok: boolean;
    detail?: string;
}
export interface AciAttestationResult {
    /** True only when every check passed and the anchor is quote-bound. */
    verified: boolean;
    /**
     * Whether the quote was shown to commit to a nonce this caller chose.
     *
     * False for a report obtained second-hand, where the nonce that produced it
     * was never published. In that case neither freshness nor the quote-to-keyset
     * REPORTDATA statement can be established. Callers must not treat the two as
     * the same evidence.
     */
    nonceBound: boolean;
    /**
     * The proven anchor, or null when any check failed. Never returned on a
     * partial pass: an anchor that is not quote-bound is not an improvement over
     * pinning, and returning one would invite treating it as though it were.
     */
    anchor: ReceiptTrustAnchor | null;
    checks: AciCheck[];
    measurements?: TdxMeasurements;
    dcap?: DcapVerifyResult;
    /** Unix seconds after which the served report is stale, when reported. */
    staleAfter: number | null;
    /** Gateway source commit named by the report, for the operator's log. */
    sourceCommit: string | null;
}
export interface VerifyAciAttestationOptions {
    /**
     * Full DCAP verification of the quote. Required by default: the whole point
     * of this function is to replace a pinned anchor with a proven one, and an
     * unverified quote proves nothing.
     */
    dcapVerifier?: DcapVerifier;
    /** Set false only when the quote was verified by other means. */
    requireDcap?: boolean;
    expectedMeasurements?: ExpectedTdxMeasurements;
    /** Seconds of tolerance when checking the report's freshness window. */
    clockSkewSeconds?: number;
    /** Override the clock, for tests. */
    now?: () => number;
}
/**
 * The exact bytes the ACI quote's `report_data` is the SHA-256 of.
 *
 * `nonce` must be the value as sent in the query string. The gateway signs the
 * URL-decoded UTF-8 text, so a caller that re-encodes or case-folds its own
 * nonce will not reproduce the digest.
 */
export declare function aciReportDataStatement(workloadId: string, workloadKeysetDigest: string, nonce: string | null): Uint8Array;
/** `sha256` of {@link aciReportDataStatement} — the 32 bytes REPORTDATA opens with. */
export declare function aciReportData(workloadId: string, workloadKeysetDigest: string, nonce: string | null): Uint8Array;
/** The bytes the workload identity key signs to endorse its own keyset. */
export declare function aciKeysetEndorsementPayload(workloadKeysetDigest: string): Uint8Array;
/**
 * Fetch a native ACI attestation report.
 *
 * `baseUrl` is the gateway's own origin, not `api.venice.ai`. No credentials
 * are sent: the endpoint is public, and the report authenticates itself.
 */
export declare function fetchAciAttestation(baseUrl: string, nonce: string, fetchImpl?: typeof fetch): Promise<AciAttestationReport>;
/** A fresh 32-byte nonce, hex encoded, in the shape the endpoint expects. */
export declare function generateAciNonce(): string;
/**
 * Verify an ACI attestation report and, if everything holds, return the
 * quote-bound trust anchor.
 *
 * Every check is reported rather than thrown, so a caller can log precisely
 * which link failed. `anchor` is null unless all of them passed.
 */
export declare function verifyAciAttestation(report: AciAttestationReport, nonce: string, options?: VerifyAciAttestationOptions): Promise<AciAttestationResult>;
/**
 * Verify a report that arrived through somebody else.
 *
 * The gateway records the report it fetched from its own upstream, and serves it
 * alongside the attested session. A relying party can still check the quote
 * against Intel's roots, its measurements and debug bit, and the internal
 * consistency of the reported keyset.
 *
 * What it cannot check is the REPORTDATA statement. The nonce the gateway sent
 * is not published, so the verifier cannot recompute the hash that binds the
 * reported workload id and keyset digest to the quote. Comparing the served
 * `report_data` with REPORTDATA would only compare two copies of the same opaque
 * bytes. Consequently this function always reports the missing binding as a
 * failed check and never returns an anchor. Publishing the original nonce would
 * establish quote-to-keyset binding, although it still would not make that nonce
 * fresh or caller-chosen from this verifier's perspective.
 */
export declare function verifyRelayedAciAttestation(report: AciAttestationReport, options?: VerifyAciAttestationOptions): Promise<AciAttestationResult>;
/**
 * Fetch a report with a fresh nonce and verify it in one step.
 *
 * The nonce is generated here so a caller cannot accidentally verify a report
 * against a nonce it did not choose, which would leave replay wide open.
 */
export declare function establishAciTrustAnchor(baseUrl: string, options?: VerifyAciAttestationOptions & {
    fetchImpl?: typeof fetch;
}): Promise<AciAttestationResult>;
//# sourceMappingURL=aci.d.ts.map