/**
 * Attested sessions — checking the gateway's verdict on the machine it forwarded to.
 *
 * A receipt's `upstream.verified` event says what the gateway found when it
 * looked at its upstream, and the receipt signature covers that. What the event
 * does not carry is the evidence behind the verdict: that lives in an attested
 * session record, named by `session_id`.
 *
 * The name is the point. A session id is content-addressed over the verified
 * material:
 *
 * ```text
 * "as_" + hex(sha256(JCS({upstream_name, endpoint, verifier_id, identity,
 *                         channel_binding, claims, evidence_digest})))
 * ```
 *
 * so the id inside a signed receipt is a commitment to the whole record,
 * including a digest of the upstream's own attestation report. The session store
 * is served publicly and unsigned, and it does not need to be signed: recomputing
 * the id is what makes a record tamper-evident, and the receipt is what makes the
 * id trustworthy.
 *
 * Fetched by id, a session also carries the evidence inline as a `data:` URI —
 * the upstream's complete ACI attestation report, quote included. A relying
 * party can authenticate the quote with DCAP, inspect its measurements, and
 * check that the public record is the one the receipt committed to.
 *
 * A critical binding stays out of reach. The nonce the gateway sent when it
 * fetched that report is not published, so the REPORTDATA statement cannot be
 * recomputed. The relying party therefore cannot prove that the reported keyset
 * — including its TLS keys — belongs to the DCAP-valid quote, or distinguish a
 * captured report from a current one. Verification remains false until that
 * nonce is available. {@link AttestedSessionResult.upstreamNonceBound} records
 * the missing caller-freshness property separately.
 */
import { type AciAttestationReport, type AciAttestationResult, type AciCheck, type VerifyAciAttestationOptions } from './aci.js';
/** Path of the unauthenticated attested-session store. */
export declare const ACI_SESSIONS_PATH = "/v1/aci/sessions";
export interface AciChannelBinding {
    type: string;
    origin?: string;
    spki_sha256?: string;
    [key: string]: unknown;
}
export interface AciClaim {
    status: 'asserted' | 'refuted' | 'unknown';
    source?: string;
    reason?: string;
}
export interface AttestedSession {
    api_version?: string;
    session_id: string;
    upstream_name: string;
    endpoint?: string;
    verifier_id: string;
    established_at?: number;
    expires_at?: number;
    identity?: Record<string, unknown>;
    channel_binding: AciChannelBinding[];
    claims: Record<string, AciClaim>;
    evidence?: {
        digest?: string;
        data?: string;
        [key: string]: unknown;
    };
}
export interface AttestedSessionResult {
    /** True only when every required binding passed. Relayed reports currently fail closed. */
    verified: boolean;
    checks: AciCheck[];
    /**
     * Checks performed on the upstream's attestation report, when the session
     * carried it. This result remains unverified while the report nonce is absent.
     * Null when no evidence was served or it could not be decoded.
     */
    upstream: AciAttestationResult | null;
    /**
     * Always false today: the nonce behind the upstream report is not published,
     * so the second hop's freshness is not established by this check.
     */
    upstreamNonceBound: boolean;
    /** Claims the gateway could not establish about the upstream. */
    unknownClaims: string[];
}
export interface VerifyAttestedSessionOptions {
    /** The `session_id` the signed receipt named. Required — it is the whole binding. */
    expectedSessionId: string;
    /** The `url_origin` the receipt named, checked against the session's endpoint. */
    expectedOrigin?: string;
    /** Verify the upstream report's quote. Omitted means the report is not checked. */
    dcapVerifier?: VerifyAciAttestationOptions['dcapVerifier'];
    /** Skip verifying the inline evidence even when it is present. */
    skipEvidence?: boolean;
    clockSkewSeconds?: number;
    now?: () => number;
}
/**
 * Recompute a session's content-addressed id.
 *
 * Timestamps are excluded so identical material dedups to one session; every
 * field named here feeds the hash, so adding or dropping one changes every id.
 */
export declare function computeAttestedSessionId(session: AttestedSession): string;
/** Fetch one attested session by id. Public endpoint; no credentials are sent. */
export declare function fetchAttestedSession(baseUrl: string, sessionId: string, fetchImpl?: typeof fetch): Promise<AttestedSession>;
/** The upstream report carried in a session's `evidence.data` URI, with its raw bytes. */
export declare function decodeSessionEvidence(session: AttestedSession): {
    bytes: Uint8Array;
    report: AciAttestationReport;
} | null;
/**
 * Verify an attested session against the id a signed receipt named.
 *
 * Reports every check rather than throwing. When the session carries the
 * upstream's report and a `dcapVerifier` is supplied, the quote and report are
 * checked and their results are folded in under an `upstream.` prefix. The
 * overall result remains false while the nonce required to bind the reported
 * keyset to REPORTDATA is unavailable.
 */
export declare function verifyAttestedSession(session: AttestedSession, options: VerifyAttestedSessionOptions): Promise<AttestedSessionResult>;
//# sourceMappingURL=session.d.ts.map