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

import { sha256 } from '@noble/hashes/sha2.js';
import { verify as secpVerify } from '@noble/secp256k1';
import { toHex, fromHex } from './crypto.js';
import { parseTdxQuote } from './attestation.js';
import {
  computeWorkloadId,
  computeWorkloadKeysetDigest,
  jcsStringify,
  type ReceiptTrustAnchor,
  type WorkloadKeyset,
} from './receipt.js';
import type {
  DcapVerifier,
  DcapVerifyResult,
  ExpectedTdxMeasurements,
  TdxMeasurements,
} from './types.js';

/** Purpose tag in the statement the quote's `report_data` covers (ACI §4). */
export const ACI_REPORT_DATA_PURPOSE = 'aci.report_data.v1';

/** Purpose tag in the payload the workload identity key endorses (ACI §4.2). */
export const ACI_KEYSET_ENDORSEMENT_PURPOSE = 'aci.keyset.endorsement.v1';

/** Path of the unauthenticated native ACI attestation endpoint. */
export const ACI_ATTESTATION_PATH = '/v1/aci/attestation';

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
    freshness?: { fetched_at?: number; stale_after?: number };
    evidence?: { quote?: string; [key: string]: unknown };
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
   * was never published — every other check still holds, but nothing rules out
   * a report captured earlier and replayed. Callers must not treat the two as
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
export function aciReportDataStatement(
  workloadId: string,
  workloadKeysetDigest: string,
  nonce: string | null
): Uint8Array {
  return new TextEncoder().encode(
    jcsStringify({
      purpose: ACI_REPORT_DATA_PURPOSE,
      workload_id: workloadId,
      workload_keyset_digest: workloadKeysetDigest,
      nonce,
    })
  );
}

/** `sha256` of {@link aciReportDataStatement} — the 32 bytes REPORTDATA opens with. */
export function aciReportData(
  workloadId: string,
  workloadKeysetDigest: string,
  nonce: string | null
): Uint8Array {
  return sha256(aciReportDataStatement(workloadId, workloadKeysetDigest, nonce));
}

/** The bytes the workload identity key signs to endorse its own keyset. */
export function aciKeysetEndorsementPayload(workloadKeysetDigest: string): Uint8Array {
  return new TextEncoder().encode(
    jcsStringify({
      purpose: ACI_KEYSET_ENDORSEMENT_PURPOSE,
      workload_keyset_digest: workloadKeysetDigest,
    })
  );
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Fetch a native ACI attestation report.
 *
 * `baseUrl` is the gateway's own origin, not `api.venice.ai`. No credentials
 * are sent: the endpoint is public, and the report authenticates itself.
 */
export async function fetchAciAttestation(
  baseUrl: string,
  nonce: string,
  fetchImpl: typeof fetch = fetch
): Promise<AciAttestationReport> {
  const url = `${baseUrl.replace(/\/+$/, '')}${ACI_ATTESTATION_PATH}?nonce=${encodeURIComponent(nonce)}`;
  const res = await fetchImpl(url);
  if (!res.ok) {
    throw new Error(`ACI attestation fetch failed (${res.status}) from ${baseUrl}`);
  }
  return (await res.json()) as AciAttestationReport;
}

/** A fresh 32-byte nonce, hex encoded, in the shape the endpoint expects. */
export function generateAciNonce(): string {
  return toHex(crypto.getRandomValues(new Uint8Array(32)));
}

/**
 * Verify an ACI attestation report and, if everything holds, return the
 * quote-bound trust anchor.
 *
 * Every check is reported rather than thrown, so a caller can log precisely
 * which link failed. `anchor` is null unless all of them passed.
 */
export async function verifyAciAttestation(
  report: AciAttestationReport,
  nonce: string,
  options: VerifyAciAttestationOptions = {}
): Promise<AciAttestationResult> {
  return runAciChecks(report, nonce, options);
}

/**
 * Verify a report that arrived through somebody else.
 *
 * The gateway records the report it fetched from its own upstream, and serves it
 * alongside the attested session. A relying party can check almost all of it:
 * the quote against Intel's roots, the digests it commits to, the endorsement,
 * the debug bit, and whether the channel the gateway bound is a key the upstream
 * actually attested.
 *
 * What it cannot check is freshness. The nonce the gateway sent is not
 * published, so the statement binding cannot be recomputed and a captured report
 * cannot be told from a current one. That gap is what `nonceBound: false`
 * records, and it is why this never returns an anchor: freshness rests on the
 * attested gateway having behaved, bounded by the session's own expiry.
 */
export async function verifyRelayedAciAttestation(
  report: AciAttestationReport,
  options: VerifyAciAttestationOptions = {}
): Promise<AciAttestationResult> {
  const result = await runAciChecks(report, undefined, options);
  return { ...result, anchor: null };
}

async function runAciChecks(
  report: AciAttestationReport,
  nonce: string | undefined,
  options: VerifyAciAttestationOptions = {}
): Promise<AciAttestationResult> {
  const {
    dcapVerifier,
    requireDcap = true,
    expectedMeasurements,
    clockSkewSeconds = 60,
    now = () => Math.floor(Date.now() / 1000),
  } = options;

  const checks: AciCheck[] = [];
  const add = (name: string, ok: boolean, detail?: string): void => {
    checks.push(detail === undefined ? { name, ok } : { name, ok, detail });
  };
  let measurements: TdxMeasurements | undefined;
  let dcap: DcapVerifyResult | undefined;

  const attestation = report?.attestation;
  const keyset = attestation?.workload_keyset;
  const quote = attestation?.evidence?.quote;
  const workloadId = report?.workload_id;
  const keysetDigest = report?.workload_keyset_digest;
  const staleAfter = attestation?.freshness?.stale_after ?? null;
  const sourceCommit = attestation?.source_provenance?.repo_commit ?? null;

  let nonceBound = false;

  const fail = (): AciAttestationResult => ({
    verified: false,
    nonceBound,
    anchor: null,
    checks,
    measurements,
    dcap,
    staleAfter,
    sourceCommit,
  });

  if (!keyset || !quote || !workloadId || !keysetDigest) {
    add(
      'report_well_formed',
      false,
      'report needs workload_id, workload_keyset_digest, attestation.workload_keyset and evidence.quote'
    );
    return fail();
  }
  add('report_well_formed', true);

  add(
    'api_version_supported',
    report.api_version === undefined || report.api_version === 'aci/1',
    report.api_version === undefined || report.api_version === 'aci/1'
      ? undefined
      : `unsupported api_version "${report.api_version}"`
  );

  // The digests the quote will be checked against have to be the ones this
  // keyset actually produces, or the binding proves something about a keyset
  // nobody is using.
  let computedDigest: string;
  let computedWorkloadId: string;
  try {
    computedDigest = computeWorkloadKeysetDigest(keyset);
    computedWorkloadId = computeWorkloadId(keyset.workload_identity.public_key);
  } catch (error: unknown) {
    add(
      'keyset_recomputes',
      false,
      `could not canonicalize keyset: ${error instanceof Error ? error.message : String(error)}`
    );
    return fail();
  }
  add(
    'keyset_digest_recomputes',
    computedDigest === keysetDigest,
    computedDigest === keysetDigest ? undefined : `computed ${computedDigest}, report says ${keysetDigest}`
  );
  add(
    'workload_id_recomputes',
    computedWorkloadId === workloadId,
    computedWorkloadId === workloadId
      ? undefined
      : `computed ${computedWorkloadId}, report says ${workloadId}`
  );

  let reportData: Uint8Array;
  let tdAttributes: Uint8Array;
  let quoteBytes: Uint8Array;
  try {
    ({ bytes: quoteBytes, reportData, tdAttributes, measurements } = parseTdxQuote(quote));
  } catch (error: unknown) {
    add('quote_parsed', false, error instanceof Error ? error.message : String(error));
    return fail();
  }
  add('quote_parsed', true);

  const debugMode = (tdAttributes[0] & 0x01) !== 0;
  add(
    'debug_mode_disabled',
    !debugMode,
    debugMode ? 'TD is running in DEBUG mode — its measurements mean nothing' : undefined
  );

  // The binding this module exists for. Skipped, never faked, when the nonce
  // behind the report is not available.
  if (nonce !== undefined) {
    const expectedReportData = aciReportData(workloadId, keysetDigest, nonce);
    nonceBound = constantTimeEqual(reportData.slice(0, 32), expectedReportData);
    add(
      'report_data_binds_keyset_and_nonce',
      nonceBound,
      nonceBound
        ? undefined
        : `quote REPORTDATA starts ${toHex(reportData.slice(0, 32))}, statement hashes to ${toHex(expectedReportData)}`
    );
  }

  // The ACI profile fills only the first 32 bytes. A report with anything in
  // the tail is not the shape this verification reasons about.
  const tailClear = reportData.slice(32, 64).every((byte) => byte === 0);
  add(
    'report_data_tail_unused',
    tailClear,
    tailClear ? undefined : `expected 32 zero bytes, got ${toHex(reportData.slice(32, 64))}`
  );

  const servedReportData = attestation?.report_data;
  if (typeof servedReportData === 'string') {
    const matches = servedReportData.toLowerCase().replace(/^0x/, '') === toHex(reportData.slice(0, 32));
    add(
      'served_report_data_matches_quote',
      matches,
      matches ? undefined : `report says ${servedReportData}, quote says ${toHex(reportData.slice(0, 32))}`
    );
  }

  // Corroborating, not load-bearing: the report_data binding above already
  // proves the digest. This catches a keyset the identity key never endorsed.
  const endorsement = attestation?.keyset_endorsement;
  if (endorsement) {
    if (endorsement.algo !== 'ecdsa-secp256k1') {
      add('keyset_endorsement', false, `unsupported endorsement algo "${endorsement.algo}"`);
    } else {
      try {
        const payloadHash = sha256(aciKeysetEndorsementPayload(keysetDigest));
        // lowS is off deliberately: a high-S endorsement is still a valid
        // signature over these bytes, and malleability buys an attacker
        // nothing here — the signature is never used as an identifier.
        const ok = secpVerify(
          fromHex(endorsement.value),
          payloadHash,
          keyset.workload_identity.public_key.public_key,
          { lowS: false }
        );
        add('keyset_endorsement', ok, ok ? undefined : 'identity key did not endorse this keyset digest');
      } catch (error: unknown) {
        add(
          'keyset_endorsement',
          false,
          `endorsement check failed: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }
  }

  if (staleAfter !== null) {
    const fresh = now() <= staleAfter + clockSkewSeconds;
    add(
      'report_fresh',
      fresh,
      fresh ? undefined : `report went stale at ${new Date(staleAfter * 1000).toISOString()}`
    );
  }

  if (dcapVerifier) {
    try {
      dcap = await dcapVerifier(quoteBytes);
      const accepted = new Set([
        'UpToDate',
        'SWHardeningNeeded',
        'ConfigurationNeeded',
        'ConfigurationAndSWHardeningNeeded',
      ]);
      const ok = accepted.has(dcap.status);
      add('dcap_verified', ok, ok ? undefined : `unacceptable TCB status ${dcap.status || 'Unknown'}`);
    } catch (error: unknown) {
      add('dcap_verified', false, error instanceof Error ? error.message : String(error));
    }
  } else if (requireDcap) {
    add(
      'dcap_verified',
      false,
      'no dcapVerifier supplied — the anchor would rest on an unverified quote'
    );
  }

  if (expectedMeasurements && measurements) {
    const entries = Object.entries(expectedMeasurements) as Array<
      [keyof TdxMeasurements, string | string[]]
    >;
    if (entries.length === 0) {
      add('measurements_allowed', false, 'expected measurement policy is empty');
    } else {
      const normalize = (value: string): string => value.toLowerCase().replace(/^0x/, '');
      const mismatched = entries
        .filter(([name, allowed]) => {
          const values = (Array.isArray(allowed) ? allowed : [allowed]).map(normalize);
          return !measurements![name] || !values.includes(normalize(measurements![name]));
        })
        .map(([name]) => name);
      add(
        'measurements_allowed',
        mismatched.length === 0,
        mismatched.length === 0 ? undefined : `mismatched: ${mismatched.join(', ')}`
      );
    }
  }

  const verified = checks.every((check) => check.ok);
  return {
    verified,
    nonceBound,
    anchor: verified && nonceBound ? { workloadId, workloadKeysetDigest: keysetDigest } : null,
    checks,
    measurements,
    dcap,
    staleAfter,
    sourceCommit,
  };
}

/**
 * Fetch a report with a fresh nonce and verify it in one step.
 *
 * The nonce is generated here so a caller cannot accidentally verify a report
 * against a nonce it did not choose, which would leave replay wide open.
 */
export async function establishAciTrustAnchor(
  baseUrl: string,
  options: VerifyAciAttestationOptions & { fetchImpl?: typeof fetch } = {}
): Promise<AciAttestationResult> {
  const { fetchImpl, ...verifyOptions } = options;
  const nonce = generateAciNonce();
  const report = await fetchAciAttestation(baseUrl, nonce, fetchImpl ?? fetch);
  return verifyAciAttestation(report, nonce, verifyOptions);
}
