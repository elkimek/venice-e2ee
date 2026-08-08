import { describe, it, expect } from 'vitest';
import { getPublicKey, signAsync, utils } from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  computeAttestedSessionId,
  decodeSessionEvidence,
  fetchAttestedSession,
  verifyAttestedSession,
  type AttestedSession,
} from './session.js';
import { aciKeysetEndorsementPayload } from './aci.js';
import { computeWorkloadId, computeWorkloadKeysetDigest, type WorkloadKeyset } from './receipt.js';
import { toHex } from './crypto.js';
import type { DcapVerifier } from './types.js';

const ORIGIN = 'https://glm-5-2.aus1-router.phala.com';
const SPKI = '0d'.repeat(32);

const identityPrivateKey = utils.randomPrivateKey();
const identityPublicKey = toHex(getPublicKey(identityPrivateKey, false));

function upstreamKeyset(spki = SPKI): WorkloadKeyset {
  return {
    workload_identity: {
      public_key: { algo: 'ecdsa-secp256k1', public_key: identityPublicKey },
      subject: null,
    },
    keyset_epoch: { version: 1, not_after: 4_000_000_000 },
    receipt_signing_keys: [
      { key_id: 'receipt-ed25519-v1', algo: 'ed25519', public_key: 'aa'.repeat(32) },
    ],
    tls_public_keys: [{ domain: 'glm-5-2.aus1-router.phala.com', spki_sha256: spki }],
  } as unknown as WorkloadKeyset;
}

function quoteWith(reportData: Uint8Array): string {
  const quote = new Uint8Array(632);
  quote[0] = 4;
  quote[4] = 0x81;
  quote.set(reportData, 568);
  return toHex(quote);
}

async function upstreamReport(keyset: WorkloadKeyset) {
  const digest = computeWorkloadKeysetDigest(keyset);
  // The nonce behind a relayed report is unknown, so REPORTDATA is opaque here —
  // only its agreement with the served value is checkable.
  const reportData = sha256(new TextEncoder().encode('whatever the gateway sent'));
  const endorsement = await signAsync(
    sha256(aciKeysetEndorsementPayload(digest)),
    identityPrivateKey
  );
  return {
    api_version: 'aci/1',
    workload_id: computeWorkloadId(keyset.workload_identity.public_key),
    workload_keyset_digest: digest,
    attestation: {
      vendor: 'router',
      tee_type: 'tdx',
      workload_keyset: keyset,
      report_data: toHex(reportData),
      keyset_endorsement: { algo: 'ecdsa-secp256k1', value: endorsement.toCompactHex() },
      source_provenance: { repo_commit: '70513c1c' },
      freshness: { fetched_at: 1_000, stale_after: 4_000_000_000 },
      evidence: { quote: quoteWith(reportData) },
    },
  };
}

function dataUri(bytes: Uint8Array): string {
  return `data:application/json;base64,${btoa(String.fromCharCode(...bytes))}`;
}

async function buildSession(overrides: {
  keyset?: WorkloadKeyset;
  bindingSpki?: string;
  endpoint?: string;
  omitEvidence?: boolean;
  tamperEvidence?: boolean;
  expiresAt?: number;
} = {}): Promise<AttestedSession> {
  const keyset = overrides.keyset ?? upstreamKeyset();
  const report = await upstreamReport(keyset);
  const bytes = new TextEncoder().encode(JSON.stringify(report));
  const digest = `sha256:${toHex(sha256(bytes))}`;

  const session = {
    api_version: 'aci/1',
    session_id: '',
    upstream_name: 'private-ai-gateway-dev',
    endpoint: overrides.endpoint ?? ORIGIN,
    verifier_id: 'aci-service/v2',
    established_at: 1_000,
    expires_at: overrides.expiresAt ?? 4_000_000_000,
    channel_binding: [
      { type: 'tls_spki_sha256', origin: ORIGIN, spki_sha256: overrides.bindingSpki ?? SPKI },
    ],
    claims: {
      tee_attested: { status: 'asserted' as const, source: 'verifier_derived', reason: 'ok' },
      gpu_attested: { status: 'unknown' as const },
    },
    evidence: overrides.omitEvidence
      ? { digest }
      : {
          digest,
          data: dataUri(
            overrides.tamperEvidence ? new TextEncoder().encode('{"tampered":true}') : bytes
          ),
        },
  } as AttestedSession;

  session.session_id = computeAttestedSessionId(session);
  return session;
}

const okDcap: DcapVerifier = async () => ({ status: 'UpToDate', advisoryIds: [] });

function failed(result: { checks: Array<{ name: string; ok: boolean }> }): string[] {
  return result.checks.filter((c) => !c.ok).map((c) => c.name);
}

describe('computeAttestedSessionId', () => {
  it('is stable and excludes timestamps so identical material dedups', async () => {
    const session = await buildSession();
    const later = { ...session, established_at: 9_999, expires_at: 9_999_999 };
    expect(computeAttestedSessionId(later)).toBe(session.session_id);
  });

  it('changes when any verified field changes', async () => {
    const session = await buildSession();
    expect(computeAttestedSessionId({ ...session, verifier_id: 'other/v1' })).not.toBe(
      session.session_id
    );
    expect(
      computeAttestedSessionId({
        ...session,
        claims: { ...session.claims, gpu_attested: { status: 'asserted' } },
      })
    ).not.toBe(session.session_id);
    expect(
      computeAttestedSessionId({
        ...session,
        evidence: { ...session.evidence, digest: 'sha256:' + '00'.repeat(32) },
      })
    ).not.toBe(session.session_id);
  });
});

describe('verifyAttestedSession', () => {
  it('checks the relayed evidence without claiming its keyset is quote-bound', async () => {
    const session = await buildSession();
    const result = await verifyAttestedSession(session, {
      expectedSessionId: session.session_id,
      expectedOrigin: ORIGIN,
      dcapVerifier: okDcap,
    });

    expect(failed(result)).toEqual([
      'upstream.report_data_binds_keyset_and_nonce',
      'channel_binding_in_attested_keyset',
    ]);
    expect(result.verified).toBe(false);
    expect(result.checks.map((c) => c.name)).toContain('upstream.dcap_verified');
    expect(result.checks.map((c) => c.name)).toContain('channel_binding_in_attested_keyset');
    expect(result.unknownClaims).toEqual(['gpu_attested']);
  });

  it('never reports the second hop as nonce-bound', async () => {
    // The gateway does not publish the nonce it sent, so a captured report
    // cannot be told from a current one. That must not read as freshness.
    const session = await buildSession();
    const result = await verifyAttestedSession(session, {
      expectedSessionId: session.session_id,
      dcapVerifier: okDcap,
    });
    expect(result.upstreamNonceBound).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({
        name: 'upstream.report_data_binds_keyset_and_nonce',
        ok: false,
      })
    );
    expect(result.upstream?.anchor).toBeNull();
  });

  it('catches a record edited after the receipt committed to it', async () => {
    const session = await buildSession();
    const tampered = {
      ...session,
      claims: { ...session.claims, gpu_attested: { status: 'asserted' as const } },
    };
    const result = await verifyAttestedSession(tampered, {
      expectedSessionId: session.session_id,
      dcapVerifier: okDcap,
    });

    expect(failed(result)).toContain('session_id_recomputes');
    expect(result.verified).toBe(false);
  });

  it('catches a self-consistent record for a different session', async () => {
    const session = await buildSession();
    const result = await verifyAttestedSession(session, {
      expectedSessionId: 'as_' + '00'.repeat(32),
      dcapVerifier: okDcap,
    });

    expect(failed(result)).toContain('session_id_matches_receipt');
    expect(failed(result)).not.toContain('session_id_recomputes');
  });

  it('catches evidence swapped under its digest', async () => {
    const session = await buildSession({ tamperEvidence: true });
    const result = await verifyAttestedSession(session, {
      expectedSessionId: session.session_id,
      dcapVerifier: okDcap,
    });

    expect(failed(result)).toContain('evidence_digest_matches');
  });

  it('catches a channel bound to a TLS key the upstream never attested', async () => {
    // A genuine report for the wrong machine is the failure this rules out.
    const session = await buildSession({ bindingSpki: 'ff'.repeat(32) });
    const result = await verifyAttestedSession(session, {
      expectedSessionId: session.session_id,
      dcapVerifier: okDcap,
    });

    expect(failed(result)).toContain('channel_binding_in_attested_keyset');
  });

  it('catches an endpoint that is not the origin the receipt named', async () => {
    const session = await buildSession({ endpoint: 'https://somewhere.else.example' });
    const result = await verifyAttestedSession(session, {
      expectedSessionId: session.session_id,
      expectedOrigin: ORIGIN,
      dcapVerifier: okDcap,
    });

    expect(failed(result)).toContain('endpoint_matches_receipt_origin');
  });

  it('says so rather than passing when the upstream quote was not checked', async () => {
    const session = await buildSession();
    const result = await verifyAttestedSession(session, {
      expectedSessionId: session.session_id,
    });

    expect(failed(result)).toContain('upstream_report_verified');
    expect(result.upstream).toBeNull();
  });

  it('reports a list-endpoint record as carrying no evidence', async () => {
    const session = await buildSession({ omitEvidence: true });
    const result = await verifyAttestedSession(session, {
      expectedSessionId: session.session_id,
      dcapVerifier: okDcap,
    });

    expect(failed(result)).toContain('evidence_present');
  });

  it('reports invalid base64 evidence without rejecting the verification promise', async () => {
    const session = await buildSession();
    session.evidence!.data = 'data:application/json;base64,%%%';

    const result = await verifyAttestedSession(session, {
      expectedSessionId: session.session_id,
      dcapVerifier: okDcap,
    });

    expect(result.verified).toBe(false);
    expect(failed(result)).toContain('evidence_decodes');
  });

  it('reports invalid JSON evidence without rejecting the verification promise', async () => {
    const session = await buildSession();
    session.evidence!.data = dataUri(new TextEncoder().encode('{not-json'));

    const result = await verifyAttestedSession(session, {
      expectedSessionId: session.session_id,
      dcapVerifier: okDcap,
    });

    expect(result.verified).toBe(false);
    expect(failed(result)).toContain('evidence_decodes');
  });

  it('reports a malformed evidence data URI without rejecting', async () => {
    const session = await buildSession();
    session.evidence!.data = 'data:application/json,{"report":true}';

    const result = await verifyAttestedSession(session, {
      expectedSessionId: session.session_id,
      dcapVerifier: okDcap,
    });

    expect(result.verified).toBe(false);
    expect(failed(result)).toContain('evidence_decodes');
  });

  it('checks the id alone when the caller skips the evidence', async () => {
    const session = await buildSession();
    const result = await verifyAttestedSession(session, {
      expectedSessionId: session.session_id,
      skipEvidence: true,
    });

    expect(failed(result)).toEqual([]);
    expect(result.upstream).toBeNull();
  });

  it('flags a record past its retention deadline', async () => {
    const session = await buildSession({ expiresAt: 1_500 });
    const result = await verifyAttestedSession(session, {
      expectedSessionId: session.session_id,
      dcapVerifier: okDcap,
      now: () => 9_000,
    });

    expect(failed(result)).toContain('session_within_retention');
  });

  it('reports a malformed record without throwing', async () => {
    const result = await verifyAttestedSession({} as AttestedSession, {
      expectedSessionId: 'as_x',
    });
    expect(result.verified).toBe(false);
    expect(failed(result)).toContain('session_well_formed');
  });
});

describe('decodeSessionEvidence', () => {
  it('returns null when the record carries only a digest', async () => {
    expect(decodeSessionEvidence(await buildSession({ omitEvidence: true }))).toBeNull();
  });
});

describe('fetchAttestedSession', () => {
  it('removes trailing base-URL slashes before appending the session path', async () => {
    let requested: string | null = null;
    const fetchImpl = (async (url: string) => {
      requested = url;
      return { ok: true, json: async () => ({}) };
    }) as unknown as typeof fetch;

    await fetchAttestedSession('https://tee.example///', 'as/x', fetchImpl);

    expect(requested).toBe('https://tee.example/v1/aci/sessions/as%2Fx');
  });

  it('names expiry rather than absence on a 404', async () => {
    const fetchImpl = (async () => ({ ok: false, status: 404 })) as unknown as typeof fetch;
    await expect(fetchAttestedSession('https://tee.example', 'as_x', fetchImpl)).rejects.toThrow(
      /expired/
    );
  });

  it('surfaces other transport failures as such', async () => {
    const fetchImpl = (async () => ({ ok: false, status: 503 })) as unknown as typeof fetch;
    await expect(fetchAttestedSession('https://tee.example', 'as_x', fetchImpl)).rejects.toThrow(
      /503/
    );
  });
});
