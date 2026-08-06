import { generateKeypair, deriveAESKey, encryptMessage, decryptChunk, toHex, } from './crypto.js';
import { decryptSSEStream } from './stream.js';
import { flattenMessageContent } from './tools.js';
import { verifyAttestation, } from './attestation.js';
const DEFAULT_BASE_URL = 'https://api.venice.ai';
const DEFAULT_SESSION_TTL = 30 * 60 * 1000; // 30 minutes
export function createVeniceE2EE(options) {
    const { apiKey, baseUrl = DEFAULT_BASE_URL, sessionTTL = DEFAULT_SESSION_TTL, verifyAttestation: shouldVerify = true, dcapVerifier, requireDcap = false, gpuVerifier, requireGpu = false, expectedMeasurements, allowPlaintextResponses = false, } = options;
    if (!shouldVerify && (requireDcap || requireGpu || expectedMeasurements)) {
        throw new Error('Attestation policy cannot be required when verifyAttestation is false');
    }
    let _session = null;
    let _pendingSession = null;
    async function fetchAttestation(modelId) {
        const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
        const nonce = toHex(nonceBytes);
        const url = `${baseUrl}/api/v1/tee/attestation?model=${encodeURIComponent(modelId)}&nonce=${nonce}`;
        const res = await fetch(url, {
            headers: { Authorization: `Bearer ${apiKey}` },
        });
        if (!res.ok)
            throw new Error(`TEE attestation failed (${res.status})`);
        const response = await res.json();
        return { response, nonceBytes };
    }
    async function createSession(modelId) {
        if (_session &&
            _session.modelId === modelId &&
            Date.now() - _session.created < sessionTTL) {
            return _session;
        }
        // Deduplicate concurrent calls for the same session
        if (_pendingSession)
            return _pendingSession;
        _pendingSession = _createSessionInner(modelId);
        try {
            return await _pendingSession;
        }
        finally {
            _pendingSession = null;
        }
    }
    async function _createSessionInner(modelId) {
        const keypair = generateKeypair();
        const { response, nonceBytes } = await fetchAttestation(modelId);
        const modelPubKeyHex = response.signing_key || response.signing_public_key;
        if (!modelPubKeyHex) {
            throw new Error('No signing key in attestation response');
        }
        // Verify attestation if enabled
        let attestation;
        if (shouldVerify) {
            attestation = await verifyAttestation(response, nonceBytes, {
                dcapVerifier,
                requireDcap,
                gpuVerifier,
                requireGpu,
                expectedMeasurements,
                expectedModelId: modelId,
            });
            if (attestation.errors.length > 0) {
                throw new Error(`TEE attestation verification failed:\n  - ${attestation.errors.join('\n  - ')}`);
            }
        }
        const aesKey = await deriveAESKey(keypair.privateKey, modelPubKeyHex);
        // Zeroize old session private key before replacing
        if (_session)
            _session.privateKey.fill(0);
        _session = {
            ...keypair,
            modelPubKeyHex,
            aesKey,
            modelId,
            created: Date.now(),
            attestation,
        };
        return _session;
    }
    async function encrypt(messages, session) {
        // Every role must be encrypted, assistant and tool included: the TEE rejects
        // a request with any plaintext message content ("E2EE decryption failed"),
        // so the whole conversation stays ciphertext end to end.
        const encryptedMessages = await Promise.all(messages.map(async ({ role, content, tool_call_id }) => {
            const encrypted = {
                role,
                content: await encryptMessage(session.aesKey, session.publicKey, flattenMessageContent(content)),
            };
            // Venice requires this opaque correlation ID on tool-role messages.
            if (role === 'tool' && tool_call_id !== undefined) {
                encrypted.tool_call_id = tool_call_id;
            }
            return encrypted;
        }));
        return {
            encryptedMessages,
            headers: {
                'X-Venice-TEE-Client-Pub-Key': session.pubKeyHex,
                'X-Venice-TEE-Model-Pub-Key': session.modelPubKeyHex,
                'X-Venice-TEE-Signing-Algo': 'ecdsa',
            },
            veniceParameters: { enable_e2ee: true },
        };
    }
    async function decrypt(hexChunk, session) {
        return decryptChunk(session.privateKey, hexChunk, allowPlaintextResponses);
    }
    async function* decryptStream(body, session) {
        yield* decryptSSEStream(body, session.privateKey, allowPlaintextResponses);
    }
    /**
     * Fetch the signed receipt for a completion.
     *
     * `requestId` is Venice's completion `id`, not one a client made up. Pair the
     * result with {@link verifyReceipt} and the attestation from the same model to
     * prove the completion came from the attested enclave.
     */
    async function fetchResponseSignature(modelId, requestId) {
        const url = `${baseUrl}/api/v1/tee/signature?model=${encodeURIComponent(modelId)}` +
            `&request_id=${encodeURIComponent(requestId)}`;
        const res = await fetch(url, { headers: { Authorization: `Bearer ${apiKey}` } });
        if (!res.ok) {
            throw new Error(`TEE signature fetch failed (${res.status}): ${await res.text()}`);
        }
        return res.json();
    }
    /**
     * Fetch the raw compatibility attestation response for a model.
     *
     * This response is not by itself a receipt trust anchor: Venice's legacy
     * quote binds the E2EE key and nonce, not the ACI workload-keyset digest.
     */
    async function attest(modelId) {
        const { response } = await fetchAttestation(modelId);
        return response;
    }
    function clearSession() {
        if (_session) {
            _session.privateKey.fill(0);
            _session = null;
        }
    }
    return {
        createSession,
        attest,
        encrypt,
        decryptChunk: decrypt,
        decryptStream,
        fetchResponseSignature,
        clearSession,
    };
}
export function isE2EEModel(modelId) {
    return modelId.startsWith('e2ee-');
}
export { verifyAttestation, deriveEthAddress } from './attestation.js';
export { verifyReceipt, receiptSigningBytes, recoverReceiptSigner, jcsStringify, sha256Prefixed, BODY_BINDING_CHECKS, hashReceiptBody, computeWorkloadId, computeWorkloadKeysetDigest, } from './receipt.js';
export { ACI_ATTESTATION_PATH, ACI_KEYSET_ENDORSEMENT_PURPOSE, ACI_REPORT_DATA_PURPOSE, aciKeysetEndorsementPayload, aciReportData, aciReportDataStatement, establishAciTrustAnchor, fetchAciAttestation, generateAciNonce, verifyAciAttestation, } from './aci.js';
export { generateKeypair, deriveAESKey, encryptMessage, decryptChunk, toHex, fromHex, } from './crypto.js';
export { decryptSSEStream } from './stream.js';
export { buildToolSystemPrompt, renderToolMessages, parseToolCalls, generateToolCallId, flattenMessageContent, ToolCallStreamParser, TOOL_CALL_OPEN, TOOL_CALL_CLOSE, TOOL_RESPONSE_OPEN, TOOL_RESPONSE_CLOSE, } from './tools.js';
//# sourceMappingURL=index.js.map