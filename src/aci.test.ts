import { describe, it, expect } from 'vitest';
import { getPublicKey, signAsync, utils } from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  aciKeysetEndorsementPayload,
  aciReportData,
  establishAciTrustAnchor,
  verifyAciAttestation,
  type AciAttestationReport,
} from './aci.js';
import { computeWorkloadId, computeWorkloadKeysetDigest } from './receipt.js';
import { toHex } from './crypto.js';
import type { WorkloadKeyset } from './receipt.js';
import type { DcapVerifier } from './types.js';

// ── Fixtures ──────────────────────────────────────────────────────────

/** A TDX quote whose REPORTDATA is the 32-byte ACI statement digest, zero padded. */
function buildAciQuote(statementDigest: Uint8Array, opts: {
  debugMode?: boolean;
  tail?: Uint8Array;
} = {}): string {
  const quote = new Uint8Array(632);
  quote[0] = 4; // version
  quote[4] = 0x81; // teeType = TDX
  if (opts.debugMode) quote[168] = 0x01;
  quote.set(statementDigest, 568);
  if (opts.tail) quote.set(opts.tail, 568 + 32);
  return toHex(quote);
}

const identityPrivateKey = utils.randomPrivateKey();
const identityPublicKey = toHex(getPublicKey(identityPrivateKey, false));

function buildKeyset(overrides: Partial<WorkloadKeyset> = {}): WorkloadKeyset {
  return {
    workload_identity: {
      public_key: { algo: 'ecdsa-secp256k1', public_key: identityPublicKey },
      subject: null,
    },
    keyset_epoch: { version: 1, not_after: 4_000_000_000 },
    receipt_signing_keys: [
      { key_id: 'receipt-ed25519-v1', algo: 'ed25519', public_key: 'aa'.repeat(32) },
    ],
    ...overrides,
  } as WorkloadKeyset;
}

const NONCE = 'a1'.repeat(32);

async function endorse(keysetDigest: string): Promise<string> {
  const hash = sha256(aciKeysetEndorsementPayload(keysetDigest));
  return (await signAsync(hash, identityPrivateKey)).toCompactHex();
}

/** A complete, internally consistent report. Individual tests break one thing. */
async function buildReport(opts: {
  nonce?: string;
  keyset?: WorkloadKeyset;
  debugMode?: boolean;
  tail?: Uint8Array;
  staleAfter?: number;
  omitEndorsement?: boolean;
  breakEndorsement?: boolean;
} = {}): Promise<AciAttestationReport> {
  const keyset = opts.keyset ?? buildKeyset();
  const workloadKeysetDigest = computeWorkloadKeysetDigest(keyset);
  const workloadId = computeWorkloadId(keyset.workload_identity.public_key);
  const digest = aciReportData(workloadId, workloadKeysetDigest, opts.nonce ?? NONCE);

  return {
    api_version: 'aci/1',
    workload_id: workloadId,
    workload_keyset_digest: workloadKeysetDigest,
    attestation: {
      vendor: 'test-gateway',
      tee_type: 'tdx',
      workload_keyset: keyset,
      report_data: toHex(digest),
      keyset_endorsement: opts.omitEndorsement
        ? undefined
        : {
            algo: 'ecdsa-secp256k1',
            value: opts.breakEndorsement ? '11'.repeat(64) : await endorse(workloadKeysetDigest),
          },
      source_provenance: { repo_commit: 'deadbeef' },
      freshness: { fetched_at: 1_000, stale_after: opts.staleAfter ?? 4_000_000_000 },
      evidence: { quote: buildAciQuote(digest, { debugMode: opts.debugMode, tail: opts.tail }) },
    },
  };
}

const okDcap: DcapVerifier = async () => ({ status: 'UpToDate', advisoryIds: [] });

function failed(result: { checks: Array<{ name: string; ok: boolean }> }): string[] {
  return result.checks.filter((c) => !c.ok).map((c) => c.name);
}

// ── Tests ─────────────────────────────────────────────────────────────

describe('verifyAciAttestation', () => {
  it('returns a quote-bound anchor when every check passes', async () => {
    const report = await buildReport();
    const result = await verifyAciAttestation(report, NONCE, { dcapVerifier: okDcap });

    expect(failed(result)).toEqual([]);
    expect(result.verified).toBe(true);
    expect(result.anchor).toEqual({
      workloadId: report.workload_id,
      workloadKeysetDigest: report.workload_keyset_digest,
    });
    expect(result.sourceCommit).toBe('deadbeef');
  });

  it('refuses a report whose quote was issued for a different nonce', async () => {
    const report = await buildReport({ nonce: 'b2'.repeat(32) });
    const result = await verifyAciAttestation(report, NONCE, { dcapVerifier: okDcap });

    expect(failed(result)).toContain('report_data_binds_keyset_and_nonce');
    expect(result.anchor).toBeNull();
  });

  it('refuses a keyset swapped after the quote was issued', async () => {
    const report = await buildReport();
    // Same digest claimed, different key material behind it.
    report.attestation!.workload_keyset!.receipt_signing_keys[0].public_key = 'bb'.repeat(32);

    const result = await verifyAciAttestation(report, NONCE, { dcapVerifier: okDcap });

    expect(failed(result)).toContain('keyset_digest_recomputes');
    expect(result.anchor).toBeNull();
  });

  it('refuses a report that claims a workload id its identity key does not produce', async () => {
    const report = await buildReport();
    report.workload_id = 'sha256:' + '00'.repeat(32);

    const result = await verifyAciAttestation(report, NONCE, { dcapVerifier: okDcap });

    expect(failed(result)).toContain('workload_id_recomputes');
  });

  it('refuses a debug-mode TD', async () => {
    const result = await verifyAciAttestation(await buildReport({ debugMode: true }), NONCE, {
      dcapVerifier: okDcap,
    });

    expect(failed(result)).toContain('debug_mode_disabled');
    expect(result.anchor).toBeNull();
  });

  it('refuses REPORTDATA carrying anything in the unused tail', async () => {
    const tail = new Uint8Array(32).fill(0x07);
    const result = await verifyAciAttestation(await buildReport({ tail }), NONCE, {
      dcapVerifier: okDcap,
    });

    expect(failed(result)).toContain('report_data_tail_unused');
  });

  it('refuses an anchor when no DCAP verifier was supplied', async () => {
    const result = await verifyAciAttestation(await buildReport(), NONCE);

    expect(failed(result)).toContain('dcap_verified');
    expect(result.anchor).toBeNull();
  });

  it('allows skipping DCAP only when the caller says the quote was verified elsewhere', async () => {
    const result = await verifyAciAttestation(await buildReport(), NONCE, { requireDcap: false });

    expect(failed(result)).toEqual([]);
    expect(result.anchor).not.toBeNull();
  });

  it('refuses a rejected TCB status', async () => {
    const outOfDate: DcapVerifier = async () => ({ status: 'OutOfDate', advisoryIds: [] });
    const result = await verifyAciAttestation(await buildReport(), NONCE, { dcapVerifier: outOfDate });

    expect(failed(result)).toContain('dcap_verified');
  });

  it('refuses an endorsement the identity key did not make', async () => {
    const result = await verifyAciAttestation(await buildReport({ breakEndorsement: true }), NONCE, {
      dcapVerifier: okDcap,
    });

    expect(failed(result)).toContain('keyset_endorsement');
  });

  it('still anchors when the gateway serves no endorsement at all', async () => {
    // The report_data binding is what proves the digest; the endorsement only
    // corroborates it.
    const result = await verifyAciAttestation(await buildReport({ omitEndorsement: true }), NONCE, {
      dcapVerifier: okDcap,
    });

    expect(failed(result)).toEqual([]);
    expect(result.anchor).not.toBeNull();
  });

  it('refuses a report past its freshness window', async () => {
    const result = await verifyAciAttestation(await buildReport({ staleAfter: 1_500 }), NONCE, {
      dcapVerifier: okDcap,
      now: () => 9_000,
    });

    expect(failed(result)).toContain('report_fresh');
  });

  it('reports a malformed envelope without throwing', async () => {
    const result = await verifyAciAttestation({} as AciAttestationReport, NONCE, {
      dcapVerifier: okDcap,
    });

    expect(result.verified).toBe(false);
    expect(result.anchor).toBeNull();
    expect(failed(result)).toContain('report_well_formed');
  });

  it('enforces a measurement allowlist when one is supplied', async () => {
    const result = await verifyAciAttestation(await buildReport(), NONCE, {
      dcapVerifier: okDcap,
      expectedMeasurements: { mrTd: 'ff'.repeat(48) },
    });

    expect(failed(result)).toContain('measurements_allowed');
  });
});

describe('establishAciTrustAnchor', () => {
  it('generates its own nonce and verifies the report against it', async () => {
    let requested: string | null = null;
    const fetchImpl = (async (url: string) => {
      requested = new URL(url).searchParams.get('nonce');
      return {
        ok: true,
        json: async () => buildReport({ nonce: requested! }),
      };
    }) as unknown as typeof fetch;

    const result = await establishAciTrustAnchor('https://tee.example/', {
      dcapVerifier: okDcap,
      fetchImpl,
    });

    expect(requested).toMatch(/^[0-9a-f]{64}$/);
    expect(result.verified).toBe(true);
    expect(result.anchor).not.toBeNull();
  });

  it('rejects a gateway that answers with a report bound to some other nonce', async () => {
    const fetchImpl = (async () => ({
      ok: true,
      json: async () => buildReport({ nonce: 'cc'.repeat(32) }),
    })) as unknown as typeof fetch;

    const result = await establishAciTrustAnchor('https://tee.example', {
      dcapVerifier: okDcap,
      fetchImpl,
    });

    expect(result.anchor).toBeNull();
    expect(failed(result)).toContain('report_data_binds_keyset_and_nonce');
  });

  it('surfaces a transport failure rather than returning a null anchor', async () => {
    const fetchImpl = (async () => ({ ok: false, status: 503 })) as unknown as typeof fetch;

    await expect(
      establishAciTrustAnchor('https://tee.example', { dcapVerifier: okDcap, fetchImpl })
    ).rejects.toThrow(/503/);
  });
});
