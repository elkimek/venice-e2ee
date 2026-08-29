# venice-e2ee

Browser-side message encryption for [Venice AI](https://venice.ai)'s E2EE inference protocol,
plus provider-neutral ACI attestation, receipt, session, and E2EE v2 primitives for reusable
encrypted-inference integrations.

The library encrypts message `content` before transmission and decrypts model-output chunks in the client. The default `binding` policy parses the TDX quote supplied by Venice and checks that the client nonce and signing-key address appear in REPORTDATA and that debug mode is off. These are structural binding checks, not quote authentication: by default the library does **not** perform full DCAP validation, validate NVIDIA evidence, enforce a code-measurement allowlist, or authenticate each response to the attested signing key unless the caller adds the relevant policy and protocol checks.

Do not treat the default `binding` result as proof of a fully verified production enclave. Venice still receives request metadata including the API credential, selected model, roles, request shape, token settings, timing, sizes, and network metadata.

See the [changelog](CHANGELOG.md) for a user-readable summary of each release and its security boundaries.

> **Note:** This library uses standard cryptographic primitives (ECDH, HKDF, AES-256-GCM) via audited implementations (`@noble/secp256k1`, Web Crypto API). No custom cryptographic primitives — just Venice's E2EE protocol extracted into a reusable package.

**Protocol:** ECDH (secp256k1) key exchange → HKDF-SHA256 key derivation → AES-256-GCM encryption

## Install

```bash
npm install venice-e2ee
```

The package is ESM-only. Node.js 24 is the runtime exercised by CI. Browser use requires Web Crypto, `fetch`, `ReadableStream`, `TextEncoder`, and `TextDecoder`.

> **Python:** See [venice-e2ee-python](https://github.com/elkimek/venice-e2ee-python) for the Python port.

Or load the versioned browser bundle from a CDN:

```html
<script type="module">
  import { createVeniceE2EE } from 'https://cdn.jsdelivr.net/npm/venice-e2ee@0.5.3/dist/venice-e2ee.browser.js';
</script>
```

To self-host it, copy `dist/venice-e2ee.browser.js` from the installed package and serve that file from your own origin.

## Usage

```js
import { createVeniceE2EE } from 'venice-e2ee';

const apiKey = 'your-venice-api-key';
const e2ee = createVeniceE2EE({ apiKey });

// Create session (fetches the quote and runs the configured verification policy)
const session = await e2ee.createSession('e2ee-qwen3-5-122b-a10b');

// Inspect attestation result
console.log(session.attestation);
// { verificationLevel: 'binding', nonceVerified: true,
//   signingKeyBound: true, dcapVerified: false,
//   measurementsVerified: null, errors: [] }

// Encrypt messages
const { encryptedMessages, headers, veniceParameters } = await e2ee.encrypt(
  [{ role: 'user', content: 'Hello from the encrypted side' }],
  session
);

// Send to Venice API
const response = await fetch('https://api.venice.ai/api/v1/chat/completions', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}`, ...headers },
  body: JSON.stringify({
    model: 'e2ee-qwen3-5-122b-a10b',
    messages: encryptedMessages,
    stream: true,
    venice_parameters: veniceParameters,
  }),
});

// Decrypt streaming response
for await (const chunk of e2ee.decryptStream(response.body, session)) {
  process.stdout.write(chunk);
}
```

## API

### `createVeniceE2EE(options)`

Creates an E2EE instance with session caching and attestation verification.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | `string` | required | Venice API key |
| `baseUrl` | `string` | `https://api.venice.ai` | API base URL |
| `sessionTTL` | `number` | `1800000` (30 min) | Session cache TTL in ms |
| `verifyAttestation` | `boolean` | `true` | Verify TEE attestation on session creation |
| `dcapVerifier` | `DcapVerifier` | — | Optional quote/certificate/TCB verifier (see below) |
| `requireDcap` | `boolean` | `false` | Fail unless the injected DCAP verifier succeeds |
| `gpuVerifier` | `GpuVerifier` | — | Optional NVIDIA GPU evidence verifier (see below) |
| `requireGpu` | `boolean` | `false` | Fail unless GPU evidence is present and the injected verifier succeeds |
| `expectedMeasurements` | `ExpectedTdxMeasurements` | — | Allowlist selected TDX measurements; requires successful DCAP verification |
| `allowPlaintextResponses` | `boolean` | `false` | Compatibility escape hatch for legacy plaintext response content |

Returns an object with:

- **`createSession(modelId)`** — Generates an ephemeral keypair, fetches TEE evidence, runs the configured checks, and derives the message-encryption key. Returns an `E2EESession` with structured verification evidence. The instance keeps one current session: repeated calls for the same model reuse it for the configured TTL, while switching models replaces it and zeroizes the previous private key.
- **`encrypt(messages, session)`** — Encrypts an array of `{role, content}` messages. Returns `{ encryptedMessages, headers, veniceParameters }`.
- **`decryptChunk(hexChunk, session)`** — Decrypts one response chunk. Non-whitespace plaintext fails closed by default.
- **`decryptStream(body, session)`** — Parses an SSE stream and yields decrypted text chunks. A successful response containing plaintext model output fails closed by default.
- **`attest(modelId)`** — Fetches Venice's raw compatibility attestation response. It is evidence, not a receipt trust anchor by itself.
- **`fetchResponseSignature(modelId, requestId)`** — Fetches the signed ACI receipt wrapper for a completion.
- **`clearSession()`** — Zeroizes the private key and clears the cached session.

## Attestation verification

When a new session is needed, `createSession` fetches a TDX quote from Venice. The default `binding` policy performs these structural checks on the supplied quote body:

1. **Nonce binding** — compares the client nonce with REPORTDATA (raw or SHA-256)
2. **Signing key binding** — confirms the signing key's Ethereum address matches REPORTDATA
3. **Debug mode rejection** — rejects TEEs running in debug mode
4. **Server cross-check** — flags negative or inconsistent Venice-reported results
5. **Model binding** — confirms the evidence names the requested model

These checks establish the internal binding of fields in the supplied quote body, but they do not prove that Intel signed that quote. Replay resistance and enclave authenticity require full DCAP verification (or equivalent verification performed outside this library). If any configured check fails, `createSession` throws. The evidence and `verificationLevel` are available on `session.attestation`.

To disable verification (not recommended):

```js
const e2ee = createVeniceE2EE({ apiKey, verifyAttestation: false });
```

### Full DCAP verification

For full TDX DCAP verification (PCK cert chain, quote signatures, TCB evaluation), install the optional peer dependency and inject the verifier:

```bash
npm install @phala/dcap-qvl@^0.6.1
```

> **Upstream dependency note:** Current `@phala/dcap-qvl` releases depend on `elliptic`, which has an open advisory affecting ECDSA signing. This adapter uses Phala only for signature verification and never gives it a signing private key, so that key-exposure mechanism is not exercised here. If your policy rejects every dependency with an open advisory regardless of reachability, leave the optional DCAP adapter disabled until Phala changes its dependency tree.

```js
import { createVeniceE2EE } from 'venice-e2ee';
import { createDcapVerifier } from 'venice-e2ee/dcap';

const e2ee = createVeniceE2EE({
  apiKey: 'your-venice-api-key',
  dcapVerifier: createDcapVerifier(),
  requireDcap: true,
});
```

The provided adapter uses Phala PCCS by default. It validates Intel DCAP quote signatures, certificate/TCB collateral, and revocation information. This is stronger than the default binding checks, but it does not establish that the measured software is approved, and it says nothing about the GPU.

### GPU attestation policy

When the attestation response carries an `nvidia_payload`, that GPU evidence can be checked against NVIDIA's root of trust rather than taken on the provider's word:

```js
import { createNvidiaVerifier } from 'venice-e2ee/nvidia';

const e2ee = createVeniceE2EE({
  apiKey: 'your-venice-api-key',
  gpuVerifier: createNvidiaVerifier(),
  requireGpu: true,
});
```

The verifier submits the payload verbatim to NVIDIA's Remote Attestation Service, which validates the GPU's report against the endorsement chain rooted in a key burned into the die and against NVIDIA's reference measurements for the running VBIOS and driver. The policy then requires `eat_nonce` in the overall and every per-GPU token to equal the nonce this session sent, plus positive `secboot`, `dbgstat: "disabled"`, `measres: "success"`, and report-nonce-match claims on every GPU named. Missing or mistyped security claims fail closed. `requireGpu: true` also fails when no GPU evidence is served at all, so a provider cannot skip the check by omitting the payload.

#### Token signature verification

By default the verdict is authenticated by TLS to `nras.attestation.nvidia.com` — sound for a call you make yourself, worth nothing for a token that reached you any other way. `createNrasTokenVerifier()` checks the ES384 signature instead, against keys fetched from NVIDIA's published key set:

```js
import { createNvidiaVerifier, createNrasTokenVerifier } from 'venice-e2ee/nvidia';

const gpuVerifier = createNvidiaVerifier({
  tokenVerifier: createNrasTokenVerifier(),
});
```

Every token is checked, overall and per-GPU, and any failure rejects the whole result — there is no path where an unverified token's claims get used. `gpu.tokensVerified` reports whether this ran. Alongside the signature it pins the algorithm to ES384 (so a token cannot negotiate itself down to `none`), requires the expected `iss` and a finite `exp`, and validates `nbf` when present.

The key set is cached for 12 hours and refetched whenever a token names a `kid` not held, rate-limited so a malformed token cannot turn into a request flood. The TTL is the maximum time a still-cached withdrawn key remains trusted. When NVIDIA publishes an `x5c` chain, the signing leaf's own roughly 48-hour validity window is enforced as an additional bound.

What this buys beyond the TLS default: the token stands on its own. It can be relayed by the provider, cached, logged, or handed to someone else, and still be checkable — which is the groundwork for verifying GPU evidence without a round trip to NVIDIA per session.

`pinnedLeafCertSha256` takes SHA-256 digests of exact NVIDIA signing leaf certificates obtained out of band. When configured, the first `x5c` certificate must match one of those fingerprints and carry the JWK's public key, so an unrelated root or intermediate appended to an unvalidated array cannot satisfy the pin. NVIDIA rotates these short-lived leaves, so operators must provision overlapping current fingerprints. `VerifiedNrasToken.chainSha256` reports the observed chain digests. Root and intermediate pinning are deliberately unsupported because that would require full RFC 5280 path validation.

#### Limits

- **The verdict is NVIDIA's, not yours.** Signature verification proves NVIDIA said it; it does not independently evaluate the GPU evidence.
- **It does not prove co-location.** Nothing binds the GPU evidence to the TDX quote in the same response beyond the shared nonce. That shows both were produced for one request, not that they came from one machine — and for Venice's E2EE models the attested CVM reports `num_gpus: 0`, so they demonstrably are not.
- **It costs a round trip** to NVIDIA per session, and discloses to NVIDIA that the evidence was checked.

### Measurement policy

Measurements are always reported in `session.attestation.measurements`. Reporting a measurement is not validating it. Callers with trusted expected values can enforce an allowlist:

```js
const e2ee = createVeniceE2EE({
  apiKey,
  dcapVerifier: createDcapVerifier(),
  requireDcap: true,
  expectedMeasurements: {
    mrTd: ['trusted-mrtd-hex'],
    rtMr0: ['trusted-rtmr0-hex'],
  },
});
```

Venice does not currently publish a stable measurement allowlist in its public E2EE guide, so consumers cannot safely invent these values.

### `isE2EEModel(modelId)`

Returns `true` if the model ID starts with `e2ee-`.

## Response receipt verification

`verifyReceipt()` verifies an ACI receipt only when the caller supplies all three trust
boundaries: an independently established workload/keyset anchor, the completion ID, and
the exact request and response bytes.

```js
import { verifyReceipt } from 'venice-e2ee';

const attestation = await e2ee.attest(modelId);
const signatureResponse = await e2ee.fetchResponseSignature(modelId, completion.id);

const verification = await verifyReceipt(signatureResponse, attestation, {
  // Pin these from a canonical ACI report whose quote/report-data binding was
  // verified independently. Do not copy them from an unverified response.
  trustAnchor: {
    workloadId: 'sha256:<trusted-workload-id>',
    workloadKeysetDigest: 'sha256:<trusted-keyset-digest>',
  },
  requestId: completion.id,
  requestBody: exactRequestBytes,
  responseBody: exactResponseBytes,
  responseHashField: 'wire_hash', // or 'cleartext_hash', chosen explicitly
});

if (!verification.verified) {
  throw new Error(JSON.stringify(verification.checks));
}
```

The verifier checks the workload id and full keyset against the trust anchor, the receipt
signature under that keyset, the mandatory completion id, and the request/response hashes.
Missing context, missing or duplicate receipt events, unsupported protocol versions, and
malformed signatures all fail closed.

> **Trust-anchor requirement:** Venice's `/api/v1/tee/attestation` compatibility quote
> binds its E2EE key and nonce, not the ACI `workload_keyset_digest`. Its self-described
> `workload_id` and `workload_keyset_digest` therefore cannot establish this trust anchor.
> Use `establishAciTrustAnchor()` below, or pin values obtained out of band. Never treat two
> provider-controlled values from the response being checked as proof.

### Establishing the anchor from the quote

The gateway also speaks the native ACI protocol, and there the quote says more than Venice's
compatibility endpoint lets on. Its `report_data` is

```text
sha256(JCS({purpose: "aci.report_data.v1", workload_id, workload_keyset_digest, nonce}))
```

so a DCAP-verified quote commits to the keyset digest directly. That turns the anchor from
something you pin into something you check:

```js
import { establishAciTrustAnchor } from 'venice-e2ee';
import { createDcapVerifier } from 'venice-e2ee/dcap';

const aci = await establishAciTrustAnchor('https://tee.redpill.ai', {
  dcapVerifier: createDcapVerifier(),
});

if (!aci.anchor) throw new Error(JSON.stringify(aci.checks));

// Venice must be serving the keyset the quote covers.
if (attestation.workload_keyset_digest !== aci.anchor.workloadKeysetDigest) {
  throw new Error('Venice reports a keyset the attested enclave did not commit to');
}
```

The endpoint is unauthenticated and lives on the gateway's own hostnames rather than behind
`api.venice.ai`. Reaching it over a different path is not a weakness: the quote authenticates
itself against Intel's roots, and the digest it binds is compared against the one Venice
reports. If those agree, the keyset Venice serves is the keyset the quote covers.

The nonce is generated inside `establishAciTrustAnchor()` so a caller cannot accidentally
verify a report against a nonce it did not choose. DCAP verification is required by default:
an anchor lifted from an unverified quote is no better than a pinned one, and `anchor` stays
null unless every check passes.

### Inspecting the second-hop evidence

A receipt's `upstream.verified` event says what the gateway found when it checked the machine
it forwarded to. The receipt signature covers that claim, but not the evidence behind it —
which lives in an attested session, named by a `session_id` that is content-addressed over
the verified material, `evidence_digest` included. So the id inside a signed receipt is a
commitment to the whole record, and the public, unsigned session store becomes
tamper-evident without needing a signature of its own.

Fetched by id, a session also carries that evidence inline: the upstream's complete ACI
report, quote and all.

```js
import { fetchAttestedSession, verifyAttestedSession } from 'venice-e2ee';

const event = receipt.event_log.find((e) => e.type === 'upstream.verified');
const session = await fetchAttestedSession('https://tee.redpill.ai', event.session_id);

const result = await verifyAttestedSession(session, {
  expectedSessionId: event.session_id,
  expectedOrigin: event.url_origin,
  dcapVerifier: createDcapVerifier(),
});
```

That recomputes the session id, checks the evidence digest, and DCAP-validates the *upstream's*
quote against Intel's roots; those checks appear under an `upstream.` prefix. It authenticates
the quote and proves that the public evidence is what the receipt committed to.

It does **not** independently verify the second hop today. The nonce the gateway used to fetch
the report is not published, so the verifier cannot recompute the REPORTDATA statement that
binds `workload_id` and `workload_keyset_digest` to the quote. Matching the served
`report_data` to REPORTDATA would only compare two copies of opaque bytes. Consequently
`result.verified` and `upstreamNonceBound` are false, no anchor is returned, and a TLS key in
the reported keyset is not described as attested.

Publishing the gateway's original nonce in the content-addressed evidence would make the
quote-to-keyset binding checkable. It still would not make that nonce caller-chosen or prove
freshness independently; freshness would continue to rest on the attested gateway's behavior
and the session retention window. A 404 on an old completion can therefore mean expiry rather
than missing evidence.

For responses transformed after leaving the gateway, the bytes in hand may not reproduce
the receipt's `cleartext_hash`. Select `wire_hash` only for the exact wire representation or
`cleartext_hash` only when the gateway's pre-encryption serialization is available; never
substitute the hash copied from the receipt itself.

### Body binding is currently unreachable behind `api.venice.ai`

Measured against the live API rather than inferred: a client of Venice's public API currently cannot
satisfy `request_body_hash_matches` or `response_body_hash_matches` with any byte
representation it can obtain.

Both fail on the E2EE path and the TEE-only path, streaming and non-streaming, with the
exact bytes POSTed and the exact bytes received. Four combinations, the same result — which
places a re-serializing hop between the caller and the enclave that issues the receipt.
Venice demonstrably re-wraps responses (it adds `cost` and `venice_parameters`), and the
request-side hashes behave the same way. Only something sitting directly in front of the ACI
gateway can reproduce these.

Every other check passes, so what a receipt establishes from this vantage point is that
**the attested enclave signed a receipt for this completion id** under a keyset matching the
trust anchor, and separately **vouched for a pair of body hashes with its quote-bound key** —
not that the bytes in hand are the ones it produced.

Callers reporting this to a human should separate the two cases. Treating an unreachable
binding as a failed verification produces an alarm on every completion, which trains people
to ignore the one that matters:

```js
import { BODY_BINDING_CHECKS } from 'venice-e2ee';

const failed = verification.checks.filter((check) => !check.ok);
const bodyBindingOnly =
  failed.length > 0 && failed.every((check) => BODY_BINDING_CHECKS.includes(check.name));
```

`verified` remains false in that case, and deliberately so — the library should not decide
that a missing binding is acceptable. That judgement belongs to the caller, who knows
whether it sits behind a re-serializing gateway.

## Provider-neutral ACI E2EE v2

The `venice-e2ee/aci/e2ee` entry point implements the field-encryption layer used by native
ACI gateways independently of Venice account, model, or routing policy:

```js
import {
  createAciE2eeClientKeyPair,
  decryptAciE2eeField,
  encryptAciE2eeField,
  generateAciE2eeNonce,
} from 'venice-e2ee/aci/e2ee';

const client = createAciE2eeClientKeyPair();
const context = {
  purpose: 'aci.e2ee.request.v2',
  model: 'provider/model',
  field: 'messages.0.content',
  nonce: generateAciE2eeNonce(),
  timestamp: Math.floor(Date.now() / 1000),
};

const ciphertext = await encryptAciE2eeField(
  'This text is encrypted before transport.',
  quoteBoundE2eePublicKey,
  context
);

// For a response, use purpose `aci.e2ee.response.v2`, the exact response id,
// response field, request nonce, and request timestamp supplied by the protocol.
const plaintext = await decryptAciE2eeField(
  encryptedResponseField,
  client.secretKey,
  responseContext
);
client.secretKey.fill(0);
```

This module performs X25519 key agreement, HKDF-SHA256 key derivation, and AES-256-GCM
field encryption with canonical ACI additional authenticated data. It does **not** choose a
provider or decide whether a key is trusted. The caller must first verify fresh attestation,
bind the exact key and workload to that evidence, enforce its own measurement and routing
policy, and reject plaintext fallback.

The API is the first provider-neutral extraction toward a multi-provider encrypted-inference
monorepo. Existing Venice exports remain compatible while provider-specific account and
transport adapters are separated incrementally.

## Function calling

Venice's E2EE gateway drops the OpenAI `tools` request parameter — a request carrying
encrypted messages reaches the model with no tool schemas attached. (The same model
returns native tool calls when the E2EE headers are absent, so this is a property of the
encrypted path.) Sending `tools` anyway would leak every schema in plaintext *and* leave
the model unable to use them.

These helpers instead carry function calling inside the encrypted channel, so tool names,
descriptions, arguments and results stay ciphertext like the rest of the conversation.

```js
import {
  createVeniceE2EE,
  buildToolSystemPrompt,
  renderToolMessages,
  ToolCallStreamParser,
} from 'venice-e2ee';

const tools = [{
  type: 'function',
  function: {
    name: 'get_weather',
    description: 'Get the current weather in a given city',
    parameters: { type: 'object', properties: { city: { type: 'string' } }, required: ['city'] },
  },
}];

// 1. Fold tool schemas and any prior tool-call history into message content.
const toolPrompt = buildToolSystemPrompt(tools, 'auto');
const messages = [
  { role: 'system', content: toolPrompt },
  ...renderToolMessages(conversation),
];

// 2. Encrypt and send as usual — no `tools` field on the request.
const { encryptedMessages, headers, veniceParameters } = await e2ee.encrypt(messages, session);

// 3. Parse tool calls back out of the decrypted stream. Pass the schemas: they
//    let the parser coerce arguments and recognise an untagged call.
const parser = new ToolCallStreamParser({ tools });
for await (const text of e2ee.decryptStream(response.body, session)) {
  const { content, toolCalls } = parser.push(text);
  if (content) process.stdout.write(content);
  for (const call of toolCalls) console.log('tool call:', call.function.name, call.function.arguments);
}
const tail = parser.flush();
// parser.sawToolCall === true  →  finish_reason should be 'tool_calls'
```

| Export | Purpose |
|---|---|
| `buildToolSystemPrompt(tools, toolChoice?)` | Render tool schemas into a system prompt. Returns `null` for `tool_choice: 'none'` or an empty list. |
| `renderToolMessages(messages)` | Fold assistant `tool_calls` and `tool` results into plain message content, dropping the plaintext `tool_calls` field. |
| `ToolCallStreamParser` | Incremental parser splitting tool-call blocks from prose. `new ToolCallStreamParser({ tools })`; `push(chunk)` → `{content, toolCalls}`; `flush()` at end of stream. |
| `parseToolCalls(text, options?)` | One-shot version for a complete response body. |
| `generateToolCallId()` | Random OpenAI-style `call_…` id. |

The model is following a prompt rather than a constrained decoder, so the parser accepts a
good deal more than the format the prompt asks for:

- tags split across stream chunks, and markdown fences around the payload
- missing closing tags, and the chained `<tool_call>{..}<tool_call>{..}</tool_call>` form
  GLM emits for parallel calls
- `<function_call>` and `<|tool_call|>` in place of `<tool_call>`
- several calls in one block, as a JSON array or a `{"tool_calls": [...]}` wrapper
- `tool_name`/`tool` for the name, `parameters`/`args`/`input` for the arguments, and the
  OpenAI-shaped `{"function": {"name", "arguments"}}` nesting
- a call emitted with no tags at all — accepted only when it names one of the tools in
  `options.tools`, so a model asked to answer in JSON still returns JSON
- a lone argument passed bare (`"arguments": "Bratislava"`), wrapped using the schema when
  the function declares exactly one parameter
- **GLM's native `<arg_key>`/`<arg_value>` body**, including the degenerate forms it
  actually produces. GLM was trained on that template and uses the same `<tool_call>` tag
  this prompt asks for, so it blends the two and the tags come out lossy — a different
  subset survives each time. All of these are verbatim from `e2ee-glm-5-2-p` and all parse:

  ```
  <tool_call>read</arg_value>filePath</arg_key><arg_value>/Users/juraj/…</arg_value></tool_call>
  <tool_call>glob<arg_key>pattern "**/opencode.json"</arg_value></tool_call>
  ```

- the same body with the tags gone entirely and only their contents left, one per line.
  Nothing marks that as a call rather than prose, so it is accepted only when the first
  line names a tool in `options.tools` and every key is one of its declared properties.

A block that yields no call is never discarded — it comes back as visible content, tags
and all. Losing it silently costs the caller the whole turn with nothing to debug.

Passing `tools` is what enables the last two; without it the parser still works, but only
on tagged blocks and without argument coercion.

A model can still emit a call that is malformed or invents a function — validate names and
arguments before acting on them.

### Low-level exports

For custom integrations, the individual crypto and attestation primitives are also exported:

```js
import {
  generateKeypair,      // secp256k1 ephemeral keypair
  deriveAESKey,         // ECDH shared secret → HKDF → AES-256-GCM key
  encryptMessage,       // AES-GCM encrypt → hex(pubkey + nonce + ciphertext)
  decryptChunk,         // per-chunk ECDH + AES-GCM decrypt
  decryptSSEStream,     // SSE parser + decryption async generator
  verifyAttestation,    // run attestation checks on a raw response
  deriveEthAddress,     // secp256k1 pubkey → Ethereum address
  toHex,
  fromHex,
} from 'venice-e2ee';
```

## How it works

```
Client                              Venice TEE (Intel TDX)
  |                                        |
  |── GET /tee/attestation?model=&nonce= ─>|
  |<── { signing_key, intel_quote, ... } ──|
  |                                        |
  |  Parse TDX quote and measurements      |
  |  Check nonce and key binding           |
  |  Reject debug mode                     |
  |  Apply optional DCAP/measurement policy|
  |                                        |
  |  generateKeypair()                     |
  |  deriveAESKey(clientPriv, teePub)      |
  |  encryptMessage(aesKey, msg)           |
  |                                        |
  |── POST /chat/completions  ────────────>|
  |   X-Venice-TEE-Client-Pub-Key: ...     |
  |   X-Venice-TEE-Model-Pub-Key: ...      |
  |   { messages: [encrypted] }            |
  |                                        |
  |<── SSE stream (per-chunk encryption) ──|
  |    each chunk: hex(ephemeralPub +       |
  |                     nonce + ciphertext) |
  |                                        |
  |  decryptChunk(clientPriv, chunk)        |
  |  → ECDH(clientPriv, chunkEphPub)       |
  |  → HKDF → AES-GCM decrypt             |
```

Each response chunk uses a fresh server ephemeral key, so every chunk requires its own ECDH key derivation.

**Every message must be encrypted, whatever its role.** Venice's published examples encrypt
only `user` and `system` messages, but a request containing any plaintext content — an
`assistant` turn from the conversation history, for instance — is rejected with
`400 E2EE decryption failed`. `encrypt()` therefore encrypts every message it is given, and
`assistant` and `tool` turns decrypt correctly inside the TEE, so the whole conversation
stays ciphertext.

## Security

**Default client-side binding checks (the quote is not authenticated until DCAP verification succeeds):**
- Signing-key address is matched against TDX REPORTDATA
- Client nonce is matched against TDX REPORTDATA
- Quotes whose body marks the TEE as running in debug mode are rejected
- ECDH intermediates are zeroized after key derivation
- Private keys are zeroized on session clear/replacement

**Not verified client-side by default:**
- TDX quote signature chain (available via optional DCAP verifier)
- NVIDIA GPU attestation (available via optional GPU verifier; NVIDIA's verdict, not an independent quote check, and not bound to the TDX quote)
- TEE code measurements
- Response receipts unless the caller supplies a workload/keyset trust anchor (see `establishAciTrustAnchor()`) and exact request/response bytes

**Visible metadata:** The library encrypts message `content`, not the surrounding HTTP request. Venice can observe authentication, model selection, roles, token and streaming settings, request structure, timing, sizes, billing information, and network metadata.

**Response origin:** AES-GCM authenticates each chunk under a key derived from the client key and the chunk's server-supplied ephemeral key. The current streaming format does not itself prove that this ephemeral key belongs to the attested enclave. Receipt verification is available as a separate, fail-closed operation with the trust-anchor and byte-binding requirements above.

## Development

```bash
npm ci
npm audit
npm test              # unit tests + optional live integration tests
npm run build         # TypeScript → dist/
npm run build:browser # single-file ESM bundle
```

Set `VENICE_API_KEY` in `.env` to run integration tests against the live API.

See [RELEASING.md](https://github.com/elkimek/venice-e2ee/blob/main/RELEASING.md) for the version, changelog, GitHub release, and npm publication process.

## Acknowledgments

- [Phala Network](https://phala.network/) — TDX DCAP quote verification is powered by [`@phala/dcap-qvl`](https://github.com/Phala-Network/dcap-qvl) (Apache-2.0), a pure JavaScript implementation of the Intel DCAP Quote Verification Library.
- [Paul Miller](https://paulmillr.com/) — ECDH key exchange uses [`@noble/secp256k1`](https://github.com/paulmillr/noble-secp256k1) and key derivation uses [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) (MIT), audited noble cryptography libraries.

## License

GPL-3.0-only — see [LICENSE](LICENSE)
