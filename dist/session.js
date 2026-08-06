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
 * the upstream's complete ACI attestation report, quote included. So a relying
 * party can verify the second hop itself rather than taking the gateway's word:
 * DCAP against Intel's roots, the digests the report commits to, its endorsement,
 * and whether the TLS key the gateway bound the channel to is one the upstream
 * actually attested for the host that was dialled.
 *
 * One thing stays out of reach. The nonce the gateway sent when it fetched that
 * report is not published, so its statement binding cannot be recomputed and a
 * captured report cannot be distinguished from a current one. Freshness of the
 * second hop rests on the attested gateway having behaved, bounded by the
 * session's own expiry. {@link AttestedSessionResult.upstreamNonceBound} records
 * that rather than letting it pass unstated.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { toHex } from './crypto.js';
import { jcsStringify } from './receipt.js';
import { verifyRelayedAciAttestation, } from './aci.js';
/** Path of the unauthenticated attested-session store. */
export const ACI_SESSIONS_PATH = '/v1/aci/sessions';
/**
 * Recompute a session's content-addressed id.
 *
 * Timestamps are excluded so identical material dedups to one session; every
 * field named here feeds the hash, so adding or dropping one changes every id.
 */
export function computeAttestedSessionId(session) {
    const material = {
        upstream_name: session.upstream_name,
        endpoint: session.endpoint ?? null,
        verifier_id: session.verifier_id,
        identity: (session.identity ?? null),
        channel_binding: session.channel_binding,
        claims: session.claims,
        evidence_digest: session.evidence?.digest ?? null,
    };
    return `as_${toHex(sha256(new TextEncoder().encode(jcsStringify(material))))}`;
}
/** Fetch one attested session by id. Public endpoint; no credentials are sent. */
export async function fetchAttestedSession(baseUrl, sessionId, fetchImpl = fetch) {
    const url = `${baseUrl.replace(/\/+$/, '')}${ACI_SESSIONS_PATH}/${encodeURIComponent(sessionId)}`;
    const res = await fetchImpl(url);
    if (!res.ok) {
        // Sessions are retained only as long as the receipts citing them, so a 404
        // on an old completion is expiry rather than absence of evidence.
        throw new Error(res.status === 404
            ? `attested session ${sessionId} is not in the store (expired, or never existed)`
            : `attested session fetch failed (${res.status}) from ${baseUrl}`);
    }
    return (await res.json());
}
/** The upstream report carried in a session's `evidence.data` URI, with its raw bytes. */
export function decodeSessionEvidence(session) {
    const data = session.evidence?.data;
    if (typeof data !== 'string')
        return null;
    const comma = data.indexOf(',');
    if (!data.startsWith('data:') || comma < 0)
        return null;
    const payload = data.slice(comma + 1);
    const binary = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return { bytes, report: JSON.parse(new TextDecoder().decode(bytes)) };
}
/** Host of a URL, or null when it will not parse. */
function originHost(value) {
    if (!value)
        return null;
    try {
        return new URL(value).host.toLowerCase();
    }
    catch {
        return null;
    }
}
/**
 * Verify an attested session against the id a signed receipt named.
 *
 * Reports every check rather than throwing. When the session carries the
 * upstream's report and a `dcapVerifier` is supplied, that report is verified
 * too and its checks are folded in under an `upstream.` prefix.
 */
export async function verifyAttestedSession(session, options) {
    const checks = [];
    const add = (name, ok, detail) => {
        checks.push(detail === undefined ? { name, ok } : { name, ok, detail });
    };
    const unknownClaims = Object.entries(session?.claims ?? {})
        .filter(([, claim]) => claim?.status === 'unknown')
        .map(([name]) => name);
    const done = (upstream) => ({
        verified: checks.every((check) => check.ok),
        checks,
        upstream,
        upstreamNonceBound: upstream?.nonceBound ?? false,
        unknownClaims,
    });
    if (!session || typeof session.session_id !== 'string' || !Array.isArray(session.channel_binding)) {
        add('session_well_formed', false, 'session record is missing session_id or channel_binding');
        return done(null);
    }
    add('session_well_formed', true);
    let recomputed;
    try {
        recomputed = computeAttestedSessionId(session);
    }
    catch (error) {
        add('session_id_recomputes', false, `could not canonicalize session: ${error instanceof Error ? error.message : String(error)}`);
        return done(null);
    }
    add('session_id_recomputes', recomputed === session.session_id, recomputed === session.session_id
        ? undefined
        : `computed ${recomputed}, record says ${session.session_id}`);
    add('session_id_matches_receipt', session.session_id === options.expectedSessionId, session.session_id === options.expectedSessionId
        ? undefined
        : `record is ${session.session_id}, receipt named ${options.expectedSessionId}`);
    if (options.expectedOrigin) {
        const matches = originHost(session.endpoint) === originHost(options.expectedOrigin);
        add('endpoint_matches_receipt_origin', matches, matches
            ? undefined
            : `session endpoint ${session.endpoint ?? 'missing'}, receipt named ${options.expectedOrigin}`);
    }
    const now = options.now ?? (() => Math.floor(Date.now() / 1000));
    if (typeof session.expires_at === 'number') {
        // A retention deadline rather than a binding-validity one, so this is
        // reported for context rather than treated as invalidating.
        const live = now() <= session.expires_at + (options.clockSkewSeconds ?? 60);
        add('session_within_retention', live, live ? undefined : 'session record is past its retention deadline');
    }
    if (options.skipEvidence)
        return done(null);
    const evidence = decodeSessionEvidence(session);
    if (!evidence) {
        // The list endpoint serves digests only; fetch by id to get the report.
        add('evidence_present', false, 'session carries no inline evidence — fetch it by id rather than from the list');
        return done(null);
    }
    add('evidence_present', true);
    const digest = `sha256:${toHex(sha256(evidence.bytes))}`;
    const digestOk = digest === session.evidence?.digest;
    add('evidence_digest_matches', digestOk, digestOk ? undefined : `computed ${digest}, session says ${session.evidence?.digest ?? 'missing'}`);
    if (!options.dcapVerifier) {
        // The report is here but nothing was verified about it. Saying so beats
        // returning a pass that looks like the second hop was checked.
        add('upstream_report_verified', false, 'no dcapVerifier supplied — the upstream quote was not checked');
        return done(null);
    }
    const upstream = await verifyRelayedAciAttestation(evidence.report, {
        dcapVerifier: options.dcapVerifier,
        clockSkewSeconds: options.clockSkewSeconds,
        now: options.now,
    });
    for (const check of upstream.checks) {
        checks.push({ ...check, name: `upstream.${check.name}` });
    }
    // The check that ties the channel the gateway used to the workload it
    // verified. Without it, a valid report for some other machine would pass.
    const tlsKeys = evidence.report.attestation?.workload_keyset?.tls_public_keys;
    const bindings = session.channel_binding.filter((b) => b.type === 'tls_spki_sha256');
    if (bindings.length === 0) {
        add('channel_binding_present', false, 'session records no TLS channel binding');
    }
    else if (!Array.isArray(tlsKeys)) {
        add('channel_binding_in_attested_keyset', false, 'upstream keyset publishes no TLS keys');
    }
    else {
        const unmatched = bindings.filter((binding) => !tlsKeys.some((key) => key.spki_sha256?.toLowerCase() === binding.spki_sha256?.toLowerCase() &&
            (originHost(binding.origin) === null || key.domain?.toLowerCase() === originHost(binding.origin))));
        add('channel_binding_in_attested_keyset', unmatched.length === 0, unmatched.length === 0
            ? undefined
            : `no attested TLS key for ${unmatched.map((b) => `${b.origin ?? '?'}/${b.spki_sha256 ?? '?'}`).join(', ')}`);
    }
    return done(upstream);
}
//# sourceMappingURL=session.js.map