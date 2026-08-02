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
import { sha256 } from '@noble/hashes/sha2.js';
import { toHex } from './crypto.js';
/**
 * RFC 8785 JSON Canonicalization Scheme.
 *
 * Object keys sort by UTF-16 code unit, which is what `Array.prototype.sort`
 * does by default, and no insignificant whitespace survives. `undefined`
 * properties are dropped the way `JSON.stringify` drops them.
 */
export function jcsStringify(value) {
    if (value === null || typeof value !== 'object')
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(jcsStringify).join(',')}]`;
    const entries = Object.keys(value)
        .filter((key) => value[key] !== undefined)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${jcsStringify(value[key])}`);
    return `{${entries.join(',')}}`;
}
/** `sha256:<hex>` over the UTF-8 bytes of `text`, the form ACI digests take. */
export function sha256Prefixed(text) {
    return `sha256:${toHex(sha256(new TextEncoder().encode(text)))}`;
}
/** The exact bytes the receipt signature covers: JCS of the receipt, minus the signature value. */
export function receiptSigningBytes(receipt) {
    const { value: _omitted, ...signatureWithoutValue } = receipt.signature;
    const forSigning = {
        ...receipt,
        signature: signatureWithoutValue,
    };
    return new TextEncoder().encode(jcsStringify(forSigning));
}
function fromHexBytes(hex) {
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++)
        out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    return out;
}
async function verifyEd25519(publicKey, signature, message) {
    const key = await crypto.subtle.importKey('raw', publicKey, 'Ed25519', false, [
        'verify',
    ]);
    return crypto.subtle.verify('Ed25519', key, signature, message);
}
/**
 * Verify a signature response against the attestation it should chain to.
 *
 * Every check is reported rather than thrown, so a caller can log a partial
 * result instead of losing the detail in an exception. `verified` is true only
 * when all of them pass.
 */
export async function verifyReceipt(signatureResponse, attestation, options = {}) {
    const checks = [];
    const add = (name, ok, detail) => {
        checks.push(detail === undefined ? { name, ok } : { name, ok, detail });
    };
    const receipt = signatureResponse?.receipt;
    if (!receipt || !receipt.signature) {
        add('receipt_present', false, 'signature response carried no receipt');
        return { verified: false, checks };
    }
    const keyset = attestation
        .attestation?.workload_keyset;
    if (!keyset) {
        add('keyset_present', false, 'attestation carried no workload_keyset');
        return { verified: false, checks };
    }
    // 1. The signing key must be one the attestation vouches for.
    const entry = (keyset.receipt_signing_keys ?? []).find((key) => key.key_id === receipt.signature.key_id);
    add('key_in_attested_keyset', Boolean(entry), entry ? undefined : `key_id "${receipt.signature.key_id}" is not in receipt_signing_keys`);
    if (entry && entry.algo !== receipt.signature.algo) {
        add('key_algo_matches', false, `receipt says ${receipt.signature.algo}, keyset says ${entry.algo}`);
    }
    else if (entry) {
        add('key_algo_matches', true);
    }
    // 2. The signature itself.
    if (entry && entry.algo === 'ed25519') {
        try {
            const ok = await verifyEd25519(fromHexBytes(entry.public_key), fromHexBytes(receipt.signature.value), receiptSigningBytes(receipt));
            add('receipt_signature', ok, ok ? undefined : 'Ed25519 verification failed');
        }
        catch (err) {
            add('receipt_signature', false, `Ed25519 unavailable or key rejected: ${err instanceof Error ? err.message : String(err)}`);
        }
    }
    else if (entry) {
        add('receipt_signature', false, `unsupported receipt signing algorithm "${entry.algo}"`);
    }
    // 3. The keyset the receipt names must be the keyset we just used — this is
    //    what ties the signing key back to the quote, since the digest is folded
    //    into the attestation's report_data.
    const digest = sha256Prefixed(jcsStringify(keyset));
    add('keyset_digest_matches', digest === receipt.workload_keyset_digest, digest === receipt.workload_keyset_digest
        ? undefined
        : `computed ${digest}, receipt says ${receipt.workload_keyset_digest}`);
    // 4. The receipt must be about the completion we actually made.
    if (options.requestId !== undefined) {
        add('chat_id_matches_request', receipt.chat_id === options.requestId, receipt.chat_id === options.requestId
            ? undefined
            : `receipt is for ${receipt.chat_id}, expected ${options.requestId}`);
    }
    // 5. Cheap cross-check that the two endpoints describe the same enclave.
    const attAddress = attestation.signing_address?.toLowerCase();
    const sigAddress = signatureResponse.signing_address?.toLowerCase();
    if (attAddress && sigAddress) {
        add('signing_address_matches_attestation', attAddress === sigAddress, attAddress === sigAddress ? undefined : `${sigAddress} vs attested ${attAddress}`);
    }
    return { verified: checks.every((check) => check.ok), checks };
}
//# sourceMappingURL=receipt.js.map