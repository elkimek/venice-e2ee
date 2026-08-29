// @ts-nocheck

// node_modules/@noble/secp256k1/index.js
var secp256k1_CURVE = {
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  h: 1n,
  a: 0n,
  b: 7n,
  Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
};
var { p: P, n: N, Gx, Gy, b: _b } = secp256k1_CURVE;
var L = 32;
var L2 = 64;
var err = (m = "") => {
  throw new Error(m);
};
var isBig = (n) => typeof n === "bigint";
var isStr = (s) => typeof s === "string";
var isBytes = (a) => a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
var abytes = (a, l) => !isBytes(a) || typeof l === "number" && l > 0 && a.length !== l ? err("Uint8Array expected") : a;
var u8n = (len) => new Uint8Array(len);
var u8fr = (buf) => Uint8Array.from(buf);
var padh = (n, pad) => n.toString(16).padStart(pad, "0");
var bytesToHex = (b) => Array.from(abytes(b)).map((e) => padh(e, 2)).join("");
var C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
var _ch = (ch) => {
  if (ch >= C._0 && ch <= C._9)
    return ch - C._0;
  if (ch >= C.A && ch <= C.F)
    return ch - (C.A - 10);
  if (ch >= C.a && ch <= C.f)
    return ch - (C.a - 10);
  return;
};
var hexToBytes = (hex) => {
  const e = "hex invalid";
  if (!isStr(hex))
    return err(e);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    return err(e);
  const array = u8n(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = _ch(hex.charCodeAt(hi));
    const n2 = _ch(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0)
      return err(e);
    array[ai] = n1 * 16 + n2;
  }
  return array;
};
var toU8 = (a, len) => abytes(isStr(a) ? hexToBytes(a) : u8fr(abytes(a)), len);
var cr = () => globalThis?.crypto;
var concatBytes = (...arrs) => {
  const r = u8n(arrs.reduce((sum, a) => sum + abytes(a).length, 0));
  let pad = 0;
  arrs.forEach((a) => {
    r.set(a, pad);
    pad += a.length;
  });
  return r;
};
var randomBytes = (len = L) => {
  const c = cr();
  return c.getRandomValues(u8n(len));
};
var big = BigInt;
var arange = (n, min, max, msg = "bad number: out of range") => isBig(n) && min <= n && n < max ? n : err(msg);
var M = (a, b = P) => {
  const r = a % b;
  return r >= 0n ? r : b + r;
};
var modN = (a) => M(a, N);
var invert = (num, md) => {
  if (num === 0n || md <= 0n)
    err("no inverse n=" + num + " mod=" + md);
  let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {
    const q = b / a, r = b % a;
    const m = x - u * q, n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  return b === 1n ? M(x, md) : err("no inverse");
};
var apoint = (p) => p instanceof Point ? p : err("Point expected");
var koblitz = (x) => M(M(x * x) * x + _b);
var afield0 = (n) => arange(n, 0n, P);
var afield = (n) => arange(n, 1n, P);
var agroup = (n) => arange(n, 1n, N);
var isEven = (y) => (y & 1n) === 0n;
var u8of = (n) => Uint8Array.of(n);
var getPrefix = (y) => u8of(isEven(y) ? 2 : 3);
var lift_x = (x) => {
  const c = koblitz(afield(x));
  let r = 1n;
  for (let num = c, e = (P + 1n) / 4n; e > 0n; e >>= 1n) {
    if (e & 1n)
      r = r * num % P;
    num = num * num % P;
  }
  return M(r * r) === c ? r : err("sqrt invalid");
};
var Point = class _Point {
  static BASE;
  static ZERO;
  px;
  py;
  pz;
  constructor(px, py, pz) {
    this.px = afield0(px);
    this.py = afield(py);
    this.pz = afield0(pz);
    Object.freeze(this);
  }
  /** Convert Uint8Array or hex string to Point. */
  static fromBytes(bytes) {
    abytes(bytes);
    let p = void 0;
    const head = bytes[0];
    const tail = bytes.subarray(1);
    const x = sliceBytesNumBE(tail, 0, L);
    const len = bytes.length;
    if (len === L + 1 && [2, 3].includes(head)) {
      let y = lift_x(x);
      const evenY = isEven(y);
      const evenH = isEven(big(head));
      if (evenH !== evenY)
        y = M(-y);
      p = new _Point(x, y, 1n);
    }
    if (len === L2 + 1 && head === 4)
      p = new _Point(x, sliceBytesNumBE(tail, L, L2), 1n);
    return p ? p.assertValidity() : err("bad point: not on curve");
  }
  /** Equality check: compare points P&Q. */
  equals(other) {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = apoint(other);
    const X1Z2 = M(X1 * Z2);
    const X2Z1 = M(X2 * Z1);
    const Y1Z2 = M(Y1 * Z2);
    const Y2Z1 = M(Y2 * Z1);
    return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
  }
  is0() {
    return this.equals(I);
  }
  /** Flip point over y coordinate. */
  negate() {
    return new _Point(this.px, M(-this.py), this.pz);
  }
  /** Point doubling: P+P, complete formula. */
  double() {
    return this.add(this);
  }
  /**
   * Point addition: P+Q, complete, exception-free formula
   * (Renes-Costello-Batina, algo 1 of [2015/1060](https://eprint.iacr.org/2015/1060)).
   * Cost: `12M + 0S + 3*a + 3*b3 + 23add`.
   */
  // prettier-ignore
  add(other) {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = apoint(other);
    const a = 0n;
    const b = _b;
    let X3 = 0n, Y3 = 0n, Z3 = 0n;
    const b3 = M(b * 3n);
    let t0 = M(X1 * X2), t1 = M(Y1 * Y2), t2 = M(Z1 * Z2), t3 = M(X1 + Y1);
    let t4 = M(X2 + Y2);
    t3 = M(t3 * t4);
    t4 = M(t0 + t1);
    t3 = M(t3 - t4);
    t4 = M(X1 + Z1);
    let t5 = M(X2 + Z2);
    t4 = M(t4 * t5);
    t5 = M(t0 + t2);
    t4 = M(t4 - t5);
    t5 = M(Y1 + Z1);
    X3 = M(Y2 + Z2);
    t5 = M(t5 * X3);
    X3 = M(t1 + t2);
    t5 = M(t5 - X3);
    Z3 = M(a * t4);
    X3 = M(b3 * t2);
    Z3 = M(X3 + Z3);
    X3 = M(t1 - Z3);
    Z3 = M(t1 + Z3);
    Y3 = M(X3 * Z3);
    t1 = M(t0 + t0);
    t1 = M(t1 + t0);
    t2 = M(a * t2);
    t4 = M(b3 * t4);
    t1 = M(t1 + t2);
    t2 = M(t0 - t2);
    t2 = M(a * t2);
    t4 = M(t4 + t2);
    t0 = M(t1 * t4);
    Y3 = M(Y3 + t0);
    t0 = M(t5 * t4);
    X3 = M(t3 * X3);
    X3 = M(X3 - t0);
    t0 = M(t3 * t1);
    Z3 = M(t5 * Z3);
    Z3 = M(Z3 + t0);
    return new _Point(X3, Y3, Z3);
  }
  /**
   * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
   * Uses {@link wNAF} for base point.
   * Uses fake point to mitigate side-channel leakage.
   * @param n scalar by which point is multiplied
   * @param safe safe mode guards against timing attacks; unsafe mode is faster
   */
  multiply(n, safe = true) {
    if (!safe && n === 0n)
      return I;
    agroup(n);
    if (n === 1n)
      return this;
    if (this.equals(G))
      return wNAF(n).p;
    let p = I;
    let f = G;
    for (let d = this; n > 0n; d = d.double(), n >>= 1n) {
      if (n & 1n)
        p = p.add(d);
      else if (safe)
        f = f.add(d);
    }
    return p;
  }
  /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
  toAffine() {
    const { px: x, py: y, pz: z } = this;
    if (this.equals(I))
      return { x: 0n, y: 0n };
    if (z === 1n)
      return { x, y };
    const iz = invert(z, P);
    if (M(z * iz) !== 1n)
      err("inverse invalid");
    return { x: M(x * iz), y: M(y * iz) };
  }
  /** Checks if the point is valid and on-curve. */
  assertValidity() {
    const { x, y } = this.toAffine();
    afield(x);
    afield(y);
    return M(y * y) === koblitz(x) ? this : err("bad point: not on curve");
  }
  /** Converts point to 33/65-byte Uint8Array. */
  toBytes(isCompressed = true) {
    const { x, y } = this.assertValidity().toAffine();
    const x32b = numTo32b(x);
    if (isCompressed)
      return concatBytes(getPrefix(y), x32b);
    return concatBytes(u8of(4), x32b, numTo32b(y));
  }
  /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
  static fromAffine(ap) {
    const { x, y } = ap;
    return x === 0n && y === 0n ? I : new _Point(x, y, 1n);
  }
  toHex(isCompressed) {
    return bytesToHex(this.toBytes(isCompressed));
  }
  static fromPrivateKey(k) {
    return G.multiply(toPrivScalar(k));
  }
  static fromHex(hex) {
    return _Point.fromBytes(toU8(hex));
  }
  get x() {
    return this.toAffine().x;
  }
  get y() {
    return this.toAffine().y;
  }
  toRawBytes(isCompressed) {
    return this.toBytes(isCompressed);
  }
};
var G = new Point(Gx, Gy, 1n);
var I = new Point(0n, 1n, 0n);
Point.BASE = G;
Point.ZERO = I;
var doubleScalarMulUns = (R, u1, u2) => {
  return G.multiply(u1, false).add(R.multiply(u2, false)).assertValidity();
};
var bytesToNumBE = (b) => big("0x" + (bytesToHex(b) || "0"));
var sliceBytesNumBE = (b, from, to) => bytesToNumBE(b.subarray(from, to));
var B256 = 2n ** 256n;
var numTo32b = (num) => hexToBytes(padh(arange(num, 0n, B256), L2));
var toPrivScalar = (pr) => {
  const num = isBig(pr) ? pr : bytesToNumBE(toU8(pr, L));
  return arange(num, 1n, N, "private key invalid 3");
};
var highS = (n) => n > N >> 1n;
var getPublicKey = (privKey, isCompressed = true) => {
  return G.multiply(toPrivScalar(privKey)).toBytes(isCompressed);
};
var Signature = class _Signature {
  r;
  s;
  recovery;
  constructor(r, s, recovery) {
    this.r = agroup(r);
    this.s = agroup(s);
    if (recovery != null)
      this.recovery = recovery;
    Object.freeze(this);
  }
  /** Create signature from 64b compact (r || s) representation. */
  static fromBytes(b) {
    abytes(b, L2);
    const r = sliceBytesNumBE(b, 0, L);
    const s = sliceBytesNumBE(b, L, L2);
    return new _Signature(r, s);
  }
  toBytes() {
    const { r, s } = this;
    return concatBytes(numTo32b(r), numTo32b(s));
  }
  /** Copy signature, with newly added recovery bit. */
  addRecoveryBit(bit) {
    return new _Signature(this.r, this.s, bit);
  }
  hasHighS() {
    return highS(this.s);
  }
  toCompactRawBytes() {
    return this.toBytes();
  }
  toCompactHex() {
    return bytesToHex(this.toBytes());
  }
  recoverPublicKey(msg) {
    return recoverPublicKey(this, msg);
  }
  static fromCompact(hex) {
    return _Signature.fromBytes(toU8(hex, L2));
  }
  assertValidity() {
    return this;
  }
  normalizeS() {
    const { r, s, recovery } = this;
    return highS(s) ? new _Signature(r, modN(-s), recovery) : this;
  }
};
var bits2int = (bytes) => {
  const delta = bytes.length * 8 - 256;
  if (delta > 1024)
    err("msg invalid");
  const num = bytesToNumBE(bytes);
  return delta > 0 ? num >> big(delta) : num;
};
var bits2int_modN = (bytes) => modN(bits2int(abytes(bytes)));
var veriOpts = { lowS: true };
var verify = (sig, msgh, pub, opts = veriOpts) => {
  let { lowS } = opts;
  if (lowS == null)
    lowS = true;
  if ("strict" in opts)
    err("option not supported");
  let sigg;
  const rs = sig && typeof sig === "object" && "r" in sig;
  if (!rs && toU8(sig).length !== L2)
    err("signature must be 64 bytes");
  try {
    sigg = rs ? new Signature(sig.r, sig.s) : Signature.fromCompact(sig);
    const h = bits2int_modN(toU8(msgh));
    const P2 = Point.fromBytes(toU8(pub));
    const { r, s } = sigg;
    if (lowS && highS(s))
      return false;
    const is = invert(s, N);
    const u1 = modN(h * is);
    const u2 = modN(r * is);
    const R = doubleScalarMulUns(P2, u1, u2).toAffine();
    const v = modN(R.x);
    return v === r;
  } catch (error) {
    return false;
  }
};
var recoverPublicKey = (sig, msgh) => {
  const { r, s, recovery } = sig;
  if (![0, 1, 2, 3].includes(recovery))
    err("recovery id invalid");
  const h = bits2int_modN(toU8(msgh, L));
  const radj = recovery === 2 || recovery === 3 ? r + N : r;
  afield(radj);
  const head = getPrefix(big(recovery));
  const Rb = concatBytes(head, numTo32b(radj));
  const R = Point.fromBytes(Rb);
  const ir = invert(radj, N);
  const u1 = modN(-h * ir);
  const u2 = modN(s * ir);
  return doubleScalarMulUns(R, u1, u2);
};
var getSharedSecret = (privA, pubB, isCompressed = true) => {
  return Point.fromBytes(toU8(pubB)).multiply(toPrivScalar(privA)).toBytes(isCompressed);
};
var hashToPrivateKey = (hash) => {
  hash = toU8(hash);
  if (hash.length < L + 8 || hash.length > 1024)
    err("expected 40-1024b");
  const num = M(bytesToNumBE(hash), N - 1n);
  return numTo32b(num + 1n);
};
var randomPrivateKey = () => hashToPrivateKey(randomBytes(L + 16));
var utils = {
  normPrivateKeyToScalar: toPrivScalar,
  isValidPrivateKey: (key) => {
    try {
      return !!toPrivScalar(key);
    } catch (e) {
      return false;
    }
  },
  randomPrivateKey,
  precompute: (w = 8, p = G) => {
    p.multiply(3n);
    w;
    return p;
  }
};
var W = 8;
var scalarBits = 256;
var pwindows = Math.ceil(scalarBits / W) + 1;
var pwindowSize = 2 ** (W - 1);
var precompute = () => {
  const points = [];
  let p = G;
  let b = p;
  for (let w = 0; w < pwindows; w++) {
    b = p;
    points.push(b);
    for (let i = 1; i < pwindowSize; i++) {
      b = b.add(p);
      points.push(b);
    }
    p = b.double();
  }
  return points;
};
var Gpows = void 0;
var ctneg = (cnd, p) => {
  const n = p.negate();
  return cnd ? n : p;
};
var wNAF = (n) => {
  const comp = Gpows || (Gpows = precompute());
  let p = I;
  let f = G;
  const pow_2_w = 2 ** W;
  const maxNum = pow_2_w;
  const mask = big(pow_2_w - 1);
  const shiftBy = big(W);
  for (let w = 0; w < pwindows; w++) {
    let wbits = Number(n & mask);
    n >>= shiftBy;
    if (wbits > pwindowSize) {
      wbits -= maxNum;
      n += 1n;
    }
    const off = w * pwindowSize;
    const offF = off;
    const offP = off + Math.abs(wbits) - 1;
    const isEven2 = w % 2 !== 0;
    const isNeg = wbits < 0;
    if (wbits === 0) {
      f = f.add(ctneg(isEven2, comp[offF]));
    } else {
      p = p.add(ctneg(isNeg, comp[offP]));
    }
  }
  return { p, f };
};

// src/crypto.ts
function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function fromHex(hex) {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex: odd length");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const byte = parseInt(hex.substring(i, i + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`Invalid hex character at position ${i}`);
    bytes[i / 2] = byte;
  }
  return bytes;
}
function generateKeypair() {
  const privateKey = utils.randomPrivateKey();
  const publicKey = getPublicKey(privateKey, false);
  const pubKeyHex = toHex(publicKey);
  return { privateKey, publicKey, pubKeyHex };
}
async function deriveAESKey(myPrivateKey, theirPublicKeyHex) {
  const sharedPoint = getSharedSecret(myPrivateKey, theirPublicKeyHex, false);
  const xCoord = sharedPoint.slice(1, 33);
  try {
    const hkdfKey = await crypto.subtle.importKey(
      "raw",
      xCoord,
      "HKDF",
      false,
      ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: new TextEncoder().encode("ecdsa_encryption")
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  } finally {
    sharedPoint.fill(0);
    xCoord.fill(0);
  }
}
async function encryptMessage(aesKey, clientPubKeyBytes, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    new TextEncoder().encode(plaintext)
  );
  const out = new Uint8Array(65 + 12 + ct.byteLength);
  out.set(clientPubKeyBytes, 0);
  out.set(iv, 65);
  out.set(new Uint8Array(ct), 77);
  return toHex(out);
}
async function decryptChunk(clientPrivateKey, hexString, allowPlaintext = false) {
  if (typeof hexString !== "string") {
    throw new TypeError("Encrypted response content must be a string");
  }
  if (!hexString || /^\s+$/.test(hexString)) {
    return hexString;
  }
  const encrypted = hexString.length >= 186 && /^[0-9a-f]+$/i.test(hexString);
  if (!encrypted) {
    if (allowPlaintext) return hexString;
    throw new Error("Venice E2EE response contained unencrypted content");
  }
  const raw = fromHex(hexString);
  if (raw[0] !== 4) {
    if (allowPlaintext) return hexString;
    throw new Error("Venice E2EE response has an invalid ephemeral public key");
  }
  const serverEphemeralPubKey = toHex(raw.slice(0, 65));
  const iv = raw.slice(65, 77);
  const ciphertext = raw.slice(77);
  const chunkKey = await deriveAESKey(clientPrivateKey, serverEphemeralPubKey);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    chunkKey,
    ciphertext
  );
  return new TextDecoder().decode(pt);
}

// src/stream.ts
async function* decryptSSEStream(body, privateKey, allowPlaintextResponses = false) {
  const reader = body.getReader();
  const decoder2 = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder2.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        const data = line.slice(6).trim();
        if (data === "[DONE]") return;
        let event;
        try {
          event = JSON.parse(data);
        } catch {
          continue;
        }
        const content = event.choices?.[0]?.delta?.content;
        if (content === void 0 || content === null) continue;
        try {
          yield await decryptChunk(privateKey, content, allowPlaintextResponses);
        } catch (e) {
          if (e instanceof DOMException && e.name === "OperationError") {
            throw new Error(
              "E2EE decryption failed \u2014 session may be stale. Clear the session and retry."
            );
          }
          throw e;
        }
      }
    }
    if (buffer.trim()) {
      if (buffer.startsWith("data: ")) {
        const data = buffer.slice(6).trim();
        if (data !== "[DONE]") {
          let event;
          try {
            event = JSON.parse(data);
          } catch {
            event = {};
          }
          const content = event.choices?.[0]?.delta?.content;
          if (content !== void 0 && content !== null) {
            try {
              yield await decryptChunk(privateKey, content, allowPlaintextResponses);
            } catch (e) {
              if (e instanceof DOMException && e.name === "OperationError") {
                throw new Error(
                  "E2EE decryption failed \u2014 session may be stale. Clear the session and retry."
                );
              }
              throw e;
            }
          }
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}

// src/tools.ts
function flattenMessageContent(content) {
  if (typeof content === "string") return content;
  if (content === null || content === void 0) return "";
  if (!Array.isArray(content)) return String(content);
  return content.map((part) => {
    if (typeof part === "string") return part;
    if (part?.type === "text" || part?.type === "input_text" || part?.type === "output_text") {
      return part.text ?? "";
    }
    if (part?.type === "refusal") return "";
    throw new Error(
      `Unsupported message content part "${part?.type}": Venice E2EE models accept text only.`
    );
  }).join("");
}
var TOOL_CALL_OPEN = "<tool_call>";
var TOOL_CALL_CLOSE = "</tool_call>";
var TOOL_RESPONSE_OPEN = "<tool_response>";
var TOOL_RESPONSE_CLOSE = "</tool_response>";
var TOOL_CALL_TAGS = [
  { open: TOOL_CALL_OPEN, close: TOOL_CALL_CLOSE },
  { open: "<function_call>", close: "</function_call>" },
  { open: "<|tool_call|>", close: "<|/tool_call|>" }
];
var UNTAGGED_HOLD_LIMIT = 64 * 1024;
function generateToolCallId() {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return `call_${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}
function buildToolSystemPrompt(tools, toolChoice = "auto") {
  if (!tools || tools.length === 0) return null;
  if (toolChoice === "none") return null;
  const schemas = tools.filter((t) => t && t.function).map((t) => JSON.stringify(t.function)).join("\n");
  if (!schemas) return null;
  let instruction;
  if (typeof toolChoice === "object" && toolChoice?.function?.name) {
    instruction = `You MUST call the function \`${toolChoice.function.name}\` now. Emit only the tool call block.`;
  } else if (toolChoice === "required") {
    instruction = "You MUST call at least one of the functions above. Emit only tool call blocks.";
  } else {
    instruction = "Call a function only when it helps answer the request. Otherwise reply normally without a tool call block.";
  }
  return `# Tools

You have access to the following functions, described as JSON schemas:

<tools>
${schemas}
</tools>

To call a function, emit a block in exactly this format:

${TOOL_CALL_OPEN}
{"name": "<function-name>", "arguments": {<json-arguments>}}
${TOOL_CALL_CLOSE}

Rules:
- \`arguments\` must be a JSON object matching the function's parameter schema,
  even when the function takes a single parameter.
- Emit the block on its own, with no surrounding prose or markdown fences.
- To call several functions, emit several blocks in a row.
- Never emit the JSON payload on its own \u2014 without the surrounding tags it is
  read as an ordinary answer and the function is not called.

Results come back as:

${TOOL_RESPONSE_OPEN}
{"id": "<id-of-the-call>", "name": "<function-name>", "result": <result>}
${TOOL_RESPONSE_CLOSE}

Match \`id\` against the call it answers when several calls are outstanding.

${instruction}`;
}
function parseArgumentsToJsonString(raw, fn) {
  let value = raw;
  if (typeof raw === "string") {
    try {
      value = JSON.parse(raw);
    } catch {
      value = raw;
    }
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return JSON.stringify(value);
  }
  if (value === void 0 || value === null || value === "") return "{}";
  const properties = fn?.parameters?.properties;
  const keys = properties && typeof properties === "object" ? Object.keys(properties) : [];
  if (keys.length === 1) return JSON.stringify({ [keys[0]]: value });
  return JSON.stringify(value);
}
function renderToolCall(tc) {
  let args = {};
  try {
    args = tc.function?.arguments ? JSON.parse(tc.function.arguments) : {};
  } catch {
    args = tc.function?.arguments ?? {};
  }
  const payload = JSON.stringify({
    ...tc.id ? { id: tc.id } : {},
    name: tc.function?.name,
    arguments: args
  });
  return `${TOOL_CALL_OPEN}
${payload}
${TOOL_CALL_CLOSE}`;
}
function renderToolMessages(messages) {
  const callNames = /* @__PURE__ */ new Map();
  for (const msg of messages) {
    if (Array.isArray(msg.tool_calls)) {
      for (const tc of msg.tool_calls) {
        if (tc?.id && tc.function?.name) callNames.set(tc.id, tc.function.name);
      }
    }
  }
  return messages.map((msg) => {
    const text = flattenMessageContent(msg.content);
    if (msg.role === "assistant" && Array.isArray(msg.tool_calls) && msg.tool_calls.length > 0) {
      const blocks = msg.tool_calls.map(renderToolCall).join("\n");
      return { role: "assistant", content: text ? `${text}
${blocks}` : blocks };
    }
    if (msg.role === "tool") {
      const name = msg.tool_call_id && callNames.get(msg.tool_call_id) || msg.name;
      const payload = name || msg.tool_call_id ? JSON.stringify({
        ...msg.tool_call_id ? { id: msg.tool_call_id } : {},
        ...name ? { name } : {},
        result: text
      }) : text;
      return {
        role: "tool",
        content: `${TOOL_RESPONSE_OPEN}
${payload}
${TOOL_RESPONSE_CLOSE}`,
        ...msg.tool_call_id ? { tool_call_id: msg.tool_call_id } : {}
      };
    }
    return { role: msg.role, content: text };
  });
}
function partialTagSuffixLength(text, tag) {
  const max = Math.min(text.length, tag.length - 1);
  for (let n = max; n > 0; n--) {
    if (text.endsWith(tag.slice(0, n))) return n;
  }
  return 0;
}
function stripFences(block) {
  const trimmed = block.trim();
  const fenced = /^```(?:json)?\s*([\s\S]*?)\s*```$/.exec(trimmed);
  return fenced ? fenced[1].trim() : trimmed;
}
function findTagOutsideJsonString(text, tag) {
  let inString = false;
  let escaped = false;
  for (let i = 0; i <= text.length - tag.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (text.startsWith(tag, i)) return i;
  }
  return -1;
}
function firstJsonValue(text) {
  const objectAt = text.indexOf("{");
  const arrayAt = text.indexOf("[");
  const start = objectAt === -1 ? arrayAt : arrayAt === -1 ? objectAt : Math.min(objectAt, arrayAt);
  if (start === -1) return null;
  const openCh = text[start];
  const closeCh = openCh === "{" ? "}" : "]";
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === openCh) depth++;
    else if (ch === closeCh && --depth === 0) return text.slice(start, i + 1);
  }
  return null;
}
function escapeJsonControlChars(text) {
  const named = {
    "\n": "\\n",
    "\r": "\\r",
    "	": "\\t",
    "\b": "\\b",
    "\f": "\\f"
  };
  let out = "";
  let inString = false;
  let escaped = false;
  for (const ch of text) {
    if (inString) {
      if (escaped) {
        escaped = false;
        out += ch;
      } else if (ch === "\\") {
        escaped = true;
        out += ch;
      } else if (ch === '"') {
        inString = false;
        out += ch;
      } else if (named[ch]) {
        out += named[ch];
      } else if (ch < " ") {
        out += `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`;
      } else {
        out += ch;
      }
      continue;
    }
    if (ch === '"') inString = true;
    out += ch;
  }
  return out;
}
function parseJsonLoose(text) {
  const variants = [text];
  const repaired = escapeJsonControlChars(text);
  if (repaired !== text) variants.push(repaired);
  for (const variant of variants) {
    try {
      return JSON.parse(variant);
    } catch {
      const candidate = firstJsonValue(variant);
      if (candidate !== null) {
        try {
          return JSON.parse(candidate);
        } catch {
        }
      }
    }
  }
  return void 0;
}
function firstString(...values) {
  for (const value of values) {
    if (typeof value === "string" && value) return value;
  }
  return void 0;
}
function firstDefined(...values) {
  for (const value of values) {
    if (value !== void 0) return value;
  }
  return void 0;
}
function toToolCalls(value, lookup) {
  if (Array.isArray(value)) {
    return value.flatMap((entry) => toToolCalls(entry, lookup));
  }
  if (!value || typeof value !== "object") return [];
  const obj = value;
  for (const key of ["tool_calls", "calls", "invocations"]) {
    if (Array.isArray(obj[key])) {
      return obj[key].flatMap((entry) => toToolCalls(entry, lookup));
    }
  }
  const fn = obj.function;
  const fnObj = fn && typeof fn === "object" ? fn : void 0;
  const name = firstString(
    obj.name,
    obj.tool_name,
    obj.tool,
    typeof fn === "string" ? fn : void 0,
    fnObj?.name
  );
  if (!name) return [];
  const rawArgs = firstDefined(
    obj.arguments,
    obj.parameters,
    obj.args,
    obj.input,
    fnObj?.arguments,
    fnObj?.parameters
  );
  return [
    {
      id: generateToolCallId(),
      type: "function",
      function: { name, arguments: parseArgumentsToJsonString(rawArgs, lookup?.get(name)) }
    }
  ];
}
function parseArgValue(raw) {
  const trimmed = raw.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    return trimmed.length > 1 && trimmed.startsWith('"') && !trimmed.endsWith('"') ? trimmed.slice(1) : trimmed;
  }
}
var ARG_TAG = /<\/?arg_(?:key|value)>/g;
var ARG_VALUE_CLOSE = "</arg_value>";
var ARG_VALUE_OPEN = "<arg_value>";
var ARG_KEY_OPEN = "<arg_key>";
var ANY_ARG_TAG = /<\/?arg_(?:key|value)>/;
var FUNCTION_NAME = /^[A-Za-z_][\w.-]*$/;
var KEY_ASSIGNMENT = /^["'\s]*([A-Za-z_][\w.-]*)["'\]\s]*[:=]\s*/;
function declaredProperties(fn) {
  const properties = fn?.parameters?.properties;
  if (!properties || typeof properties !== "object") return null;
  return new Set(Object.keys(properties));
}
function parseArgKeyValueBody(text, lookup) {
  ARG_TAG.lastIndex = 0;
  const firstTag = ARG_TAG.exec(text);
  if (!firstTag) return [];
  const name = text.slice(0, firstTag.index).trim();
  if (!FUNCTION_NAME.test(name)) return [];
  const declared = declaredProperties(lookup?.get(name));
  const args = {};
  let pendingKey = null;
  const cleanKey = (key) => key.trim().replace(/^"|"$/g, "");
  const takeKey = (segment) => {
    const trimmed = segment.trim();
    if (!trimmed) return;
    const assigned = KEY_ASSIGNMENT.exec(trimmed);
    if (assigned) {
      args[assigned[1]] = parseArgValue(trimmed.slice(assigned[0].length));
      pendingKey = null;
      return;
    }
    const gap = trimmed.search(/\s/);
    if (gap !== -1) {
      args[cleanKey(trimmed.slice(0, gap))] = parseArgValue(trimmed.slice(gap + 1));
      pendingKey = null;
      return;
    }
    pendingKey = cleanKey(trimmed);
  };
  ARG_TAG.lastIndex = firstTag.index;
  for (let tag = ARG_TAG.exec(text); tag !== null; ) {
    const start = ARG_TAG.lastIndex;
    const next = ARG_TAG.exec(text);
    const segment = text.slice(start, next ? next.index : text.length);
    if (tag[0] === "<arg_value>") {
      if (pendingKey !== null) {
        const rest = text.slice(start);
        const nextKeyAt = rest.indexOf(ARG_KEY_OPEN);
        const window = nextKeyAt === -1 ? rest : rest.slice(0, nextKeyAt);
        const closes = window.split(ARG_VALUE_CLOSE).length - 1;
        const reopens = window.split(ARG_VALUE_OPEN).length - 1;
        if (reopens > 0 || closes > 1 || closes === 0 && nextKeyAt !== -1) return [];
        const close = window.indexOf(ARG_VALUE_CLOSE);
        args[pendingKey] = parseArgValue(close === -1 ? window : window.slice(0, close));
        pendingKey = null;
        ARG_TAG.lastIndex = start + (close === -1 ? window.length : close);
        tag = ARG_TAG.exec(text);
        continue;
      } else {
        const assigned = KEY_ASSIGNMENT.exec(segment.trim());
        if (!assigned || !declared?.has(assigned[1])) {
        } else if (ANY_ARG_TAG.test(segment.slice(assigned[0].length))) {
          return [];
        } else {
          takeKey(segment);
        }
      }
    } else if (tag[0] === "<arg_key>" || pendingKey === null) {
      takeKey(segment);
    }
    tag = next;
  }
  if (Object.keys(args).length === 0) return [];
  return [
    {
      id: generateToolCallId(),
      type: "function",
      function: { name, arguments: parseArgumentsToJsonString(args, lookup?.get(name)) }
    }
  ];
}
var ONLY_ARG_TAGS = /^(?:<\/?arg_(?:key|value)>)+$/;
var LEADING_ARG_TAGS = /^(?:<\/?arg_(?:key|value)>)+/;
function quoteBareKeys(text) {
  let out = "";
  let inString = false;
  let escaped = false;
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (inString) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      i++;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      i++;
      continue;
    }
    const key = /^([A-Za-z_][\w.-]*)(\s*:)/.exec(text.slice(i));
    if (key && /[{,[]\s*$/.test(out)) {
      out += `"${key[1]}"${key[2]}`;
      i += key[0].length;
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}
function parseNameThenJsonBody(text, lookup) {
  if (!lookup || lookup.size === 0) return [];
  const body = text.trim();
  const name = [...lookup.keys()].sort((a, b) => b.length - a.length).find((candidate) => body.startsWith(candidate));
  if (!name) return [];
  const rest = body.slice(name.length).trim();
  const inner = rest.startsWith("(") ? rest.replace(/^\(/, "").replace(/\)\s*$/, "") : rest.startsWith("{") ? rest.replace(/^\{/, "").replace(/\}\s*$/, "") : null;
  if (inner === null) return [];
  const parsed = parseJsonLoose(quoteBareKeys(`{${inner}}`));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return [];
  return [
    {
      id: generateToolCallId(),
      type: "function",
      function: {
        name,
        arguments: parseArgumentsToJsonString(parsed, lookup.get(name))
      }
    }
  ];
}
function parseLineDelimitedBody(text, lookup) {
  if (!lookup || lookup.size === 0) return [];
  const lines = text.split("\n").map((line) => line.trim()).filter(Boolean);
  while (lines.length > 0 && ONLY_ARG_TAGS.test(lines[lines.length - 1])) lines.pop();
  if (lines.length < 3) return [];
  const name = lines[0];
  const fn = lookup.get(name);
  if (!fn) return [];
  const rest = lines.slice(1);
  if (rest.length % 2 !== 0) return [];
  const properties = fn.parameters?.properties;
  if (!properties || typeof properties !== "object") return [];
  const declared = new Set(Object.keys(properties));
  const args = {};
  for (let i = 0; i < rest.length; i += 2) {
    const key = rest[i].replace(LEADING_ARG_TAGS, "");
    if (!declared.has(key)) return [];
    args[key] = parseArgValue(rest[i + 1]);
  }
  return [
    {
      id: generateToolCallId(),
      type: "function",
      function: { name, arguments: parseArgumentsToJsonString(args, fn) }
    }
  ];
}
function looksLikeJsonStart(text) {
  const trimmed = text.trimStart();
  if (!trimmed) return true;
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) return true;
  return "```json".startsWith(trimmed.slice(0, 7)) && trimmed.startsWith("`");
}
var ToolCallStreamParser = class {
  buffer = "";
  /** The tag pair that opened the block being accumulated, if any. */
  openTag = null;
  calls = [];
  lookup = /* @__PURE__ */ new Map();
  /** Content withheld while it might still turn out to be an untagged call. */
  held = "";
  /** Once open, content streams straight through with no further inspection. */
  gateOpen;
  constructor(options = {}) {
    for (const tool of options.tools ?? []) {
      if (tool?.function?.name) this.lookup.set(tool.function.name, tool.function);
    }
    this.gateOpen = this.lookup.size === 0;
  }
  /** Feed the next decrypted text chunk. */
  push(chunk) {
    this.buffer += chunk;
    let raw = "";
    const toolCalls = [];
    for (; ; ) {
      if (!this.openTag) {
        const opened = findFirst(this.buffer, (tag) => this.buffer.indexOf(tag.open));
        if (!opened) {
          const hold = maxPartialTagSuffix(this.buffer);
          raw += this.buffer.slice(0, this.buffer.length - hold);
          this.buffer = hold ? this.buffer.slice(this.buffer.length - hold) : "";
          break;
        }
        raw += this.buffer.slice(0, opened.index);
        this.buffer = this.buffer.slice(opened.index + opened.tag.open.length);
        this.openTag = opened.tag;
      } else {
        const close = findTagOutsideJsonString(this.buffer, this.openTag.close);
        const chainedOpen = findFirst(
          this.buffer,
          (tag) => findTagOutsideJsonString(this.buffer, tag.open)
        );
        const nextOpen = chainedOpen ? chainedOpen.index : -1;
        const closesFirst = close !== -1 && (nextOpen === -1 || close <= nextOpen);
        if (!closesFirst && nextOpen === -1) break;
        const end = closesFirst ? close : nextOpen;
        const skip = closesFirst ? this.openTag.close.length : chainedOpen.tag.open.length;
        const block = this.buffer.slice(0, end);
        const consumed = this.openTag;
        this.buffer = this.buffer.slice(end + skip);
        this.openTag = closesFirst ? null : chainedOpen.tag;
        const calls = this.parseBlocks(block);
        if (calls.length > 0) {
          toolCalls.push(...calls);
          this.calls.push(...calls);
        } else {
          raw += consumed.open + block + (closesFirst ? consumed.close : "");
        }
      }
    }
    const gated = this.gate(raw, toolCalls.length > 0, false);
    return { content: gated.content, toolCalls: [...toolCalls, ...gated.toolCalls] };
  }
  /**
   * Finish the stream. Returns any trailing content still held back, plus tool
   * calls recovered from an unterminated block if the model omitted the closing
   * tag (some models stop right after the JSON).
   */
  flush() {
    const toolCalls = [];
    let raw = "";
    if (this.openTag) {
      let block = this.buffer;
      const plainClose = this.buffer.indexOf(this.openTag.close);
      if (plainClose !== -1) block = this.buffer.slice(0, plainClose);
      const calls = this.parseBlocks(block);
      if (calls.length > 0) {
        toolCalls.push(...calls);
        this.calls.push(...calls);
      } else {
        raw = this.openTag.open + this.buffer;
      }
    } else {
      raw = this.buffer;
    }
    this.buffer = "";
    this.openTag = null;
    const gated = this.gate(raw, toolCalls.length > 0, true);
    return { content: gated.content, toolCalls: [...toolCalls, ...gated.toolCalls] };
  }
  /** Every tool call parsed so far. */
  get toolCalls() {
    return this.calls;
  }
  /** True once any tool call has been parsed (drives `finish_reason`). */
  get sawToolCall() {
    return this.calls.length > 0;
  }
  /**
   * Decide how much plain content may be released.
   *
   * A model that ignores the tag format and answers with the raw JSON payload is
   * the most common way prompt-driven tool calling fails, so content that starts
   * like JSON is withheld until it either completes into a call to a declared
   * tool or proves to be something else. Everything else opens the gate on the
   * first chunk and streams normally from then on.
   */
  gate(text, sawTaggedCall, atEnd) {
    if (this.gateOpen) return { content: text, toolCalls: [] };
    if (sawTaggedCall) {
      this.gateOpen = true;
      const content = this.held + text;
      this.held = "";
      return { content, toolCalls: [] };
    }
    this.held += text;
    const release = () => {
      this.gateOpen = true;
      const content = this.held;
      this.held = "";
      return { content, toolCalls: [] };
    };
    if (!looksLikeJsonStart(this.held)) return release();
    if (this.held.length > UNTAGGED_HOLD_LIMIT) return release();
    const candidate = firstJsonValue(stripFences(this.held));
    if (candidate === null) return atEnd ? release() : { content: "", toolCalls: [] };
    const calls = this.parseBlocks(this.held).filter(
      (call) => this.lookup.has(call.function.name)
    );
    if (calls.length === 0) return release();
    this.gateOpen = true;
    this.held = "";
    this.calls.push(...calls);
    return { content: "", toolCalls: calls };
  }
  parseBlocks(block) {
    const text = stripFences(block);
    if (!text) return [];
    const value = parseJsonLoose(text);
    if (value !== void 0) {
      const calls = toToolCalls(value, this.lookup);
      if (calls.length > 0) return calls;
    }
    const tagged = parseArgKeyValueBody(text, this.lookup);
    if (tagged.length > 0) return tagged;
    const jsonBody = parseNameThenJsonBody(text, this.lookup);
    if (jsonBody.length > 0) return jsonBody;
    return parseLineDelimitedBody(text, this.lookup);
  }
};
function findFirst(text, locate) {
  let best = null;
  for (const tag of TOOL_CALL_TAGS) {
    const index = locate(tag);
    if (index !== -1 && (best === null || index < best.index)) best = { index, tag };
  }
  return best;
}
function maxPartialTagSuffix(text) {
  let longest = 0;
  for (const tag of TOOL_CALL_TAGS) {
    longest = Math.max(longest, partialTagSuffixLength(text, tag.open));
  }
  return longest;
}
function parseToolCalls(text, options = {}) {
  const parser = new ToolCallStreamParser(options);
  const a = parser.push(text);
  const b = parser.flush();
  return {
    content: a.content + b.content,
    toolCalls: [...a.toolCalls, ...b.toolCalls]
  };
}

// node_modules/@noble/hashes/_u64.js
var U32_MASK64 = /* @__PURE__ */ (() => BigInt(2 ** 32 - 1))();
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
var fromNumH = (n) => n / 2 ** 32 | 0;
var fromNumL = (n) => n >>> 0;
function setU64FromNum(view, byteOffset, n, isLE2) {
  const h = fromNumH(n);
  const l = fromNumL(n);
  view.setUint32(byteOffset, isLE2 ? l : h, isLE2);
  view.setUint32(byteOffset + 4, isLE2 ? h : l, isLE2);
}

// node_modules/@noble/hashes/utils.js
function isBytes2(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
var atitle = (title) => title ? `"${title}" ` : "";
function anumber(n, title = "") {
  if (typeof n !== "number")
    throw new TypeError(atitle(title) + "expected number, got " + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
  return n;
}
function abool(value, title = "") {
  if (typeof value !== "boolean")
    throw new TypeError(atitle(title) + "expected boolean, got type=" + typeof value);
  return value;
}
function abytes2(value, length, title = "") {
  if (isBytes2(value) && (length === void 0 || value.length === length))
    return value;
  if (length !== void 0)
    anumber(length, "length");
  const bytes = isBytes2(value);
  const ofLen = length !== void 0 ? ` of length ${length}` : "";
  const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
  const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
  if (!bytes)
    throw new TypeError(message);
  throw new RangeError(message);
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new TypeError("expected hash wrapped by utils.createHasher");
  anumber(h.outputLen);
  anumber(h.blockLen);
  if (h.outputLen < 1 || h.blockLen < 1)
    throw new Error("hash blockLen / outputLen must be >= 1");
}
var aobject = (value, label) => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
};
var aopts = (value, label) => {
  aobject(value, label);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null)
    throw new TypeError(`"${label}" expected plain object`);
  if (Object.hasOwn(value, "__proto__"))
    throw new TypeError(`"${label}.__proto__" is not allowed`);
};
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("hash was destroyed");
  if (checkFinished && instance.finished)
    throw new Error("digest() was already called");
}
function aoutput(out, instance) {
  abytes2(out, void 0, "output");
  const min = instance.outputLen;
  if (!(out.length >= min)) {
    throw new RangeError('"output" expected length >= ' + min);
  }
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
var hasHexBuiltin = /* @__PURE__ */ (() => (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
))();
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex2(bytes) {
  abytes2(bytes);
  if (hasHexBuiltin)
    return bytes.toHex();
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}
function asciiToBase16(ch) {
  return ch >= 48 && ch <= 57 ? ch - 48 : ch >= 65 && ch <= 70 ? ch - (65 - 10) : ch >= 97 && ch <= 102 ? ch - (97 - 10) : void 0;
}
function hexToBytes2(hex) {
  if (typeof hex !== "string")
    throw new TypeError("hex string expected, got " + typeof hex);
  if (hasHexBuiltin) {
    try {
      return Uint8Array.fromHex(hex);
    } catch (error) {
      if (error instanceof SyntaxError)
        throw new RangeError(error.message);
      throw error;
    }
  }
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new RangeError("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex[hi] + hex[hi + 1];
      throw new RangeError('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function checkOpts(defaults, opts, title = "opts") {
  aopts(defaults, "defaults");
  if (opts !== void 0)
    aopts(opts, title);
  const merged = Object.assign(/* @__PURE__ */ Object.create(null), defaults, opts);
  return merged;
}
function createHasher(hashCons, info = {}) {
  if (typeof hashCons !== "function")
    throw new TypeError('"hashCons" expected function, got type=' + typeof hashCons);
  info = checkOpts({}, info, "info");
  const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
  const tmp = hashCons(void 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.canXOF = tmp.canXOF;
  hashC.create = (opts) => hashCons(opts);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}
function randomBytes2(bytesLength = 32) {
  anumber(bytesLength, "bytesLength");
  const cr2 = typeof globalThis === "object" ? globalThis.crypto : null;
  if (typeof cr2?.getRandomValues !== "function")
    throw new Error("crypto.getRandomValues must be defined");
  if (bytesLength > 65536)
    throw new RangeError(`"bytesLength" expected <= 65536, got ${bytesLength}`);
  return cr2.getRandomValues(new Uint8Array(bytesLength));
}
var oidNist = (suffix) => ({
  // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
  // Larger suffix values would need base-128 OID encoding and a different length byte.
  oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
});

// node_modules/@noble/hashes/sha3.js
var _0n = BigInt(0);
var _1n = BigInt(1);
var _2n = BigInt(2);
var _7n = BigInt(7);
var _256n = BigInt(256);
var _0x71n = BigInt(113);
var SHA3_PI = [];
var SHA3_ROTL = [];
var _SHA3_IOTA = [];
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
  let t = _0n;
  for (let j = 0; j < 7; j++) {
    R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
    if (R & _2n)
      t ^= _1n << (_1n << BigInt(j)) - _1n;
  }
  _SHA3_IOTA.push(t);
}
var IOTAS = split(_SHA3_IOTA, true);
var SHA3_IOTA_H = IOTAS[0];
var SHA3_IOTA_L = IOTAS[1];
var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;
var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
var B = new Uint32Array(5 * 2);
function keccakP(s, rounds = 24) {
  if (!(s instanceof Uint32Array))
    throw new TypeError('"s" expected Uint32Array(50), got type=' + typeof s);
  if (s.length !== 50)
    throw new RangeError('"s" expected Uint32Array(50), got length=' + s.length);
  anumber(rounds, "rounds");
  if (rounds < 1 || rounds > 24)
    throw new Error('"rounds" expected integer 1..24');
  for (let round = 24 - rounds; round < 24; round++) {
    for (let x = 0; x < 10; x++)
      B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0; x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0; y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    let curH = s[2];
    let curL = s[3];
    for (let t = 0; t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    for (let y = 0; y < 50; y += 10) {
      const b0 = s[y], b1 = s[y + 1], b2 = s[y + 2], b3 = s[y + 3];
      s[y] ^= ~s[y + 2] & s[y + 4];
      s[y + 1] ^= ~s[y + 3] & s[y + 5];
      s[y + 2] ^= ~s[y + 4] & s[y + 6];
      s[y + 3] ^= ~s[y + 5] & s[y + 7];
      s[y + 4] ^= ~s[y + 6] & s[y + 8];
      s[y + 5] ^= ~s[y + 7] & s[y + 9];
      s[y + 6] ^= ~s[y + 8] & b0;
      s[y + 7] ^= ~s[y + 9] & b1;
      s[y + 8] ^= ~b0 & b2;
      s[y + 9] ^= ~b1 & b3;
    }
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  clean(B);
}
var Keccak = class _Keccak {
  state;
  pos = 0;
  posOut = 0;
  finished = false;
  state32;
  destroyed = false;
  blockLen;
  suffix;
  outputLen;
  canXOF;
  enableXOF = false;
  rounds;
  // NOTE: we accept arguments in bytes instead of bits here.
  constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
    anumber(blockLen, "blockLen");
    anumber(suffix, "suffix");
    anumber(rounds, "rounds");
    abool(enableXOF, "enableXOF");
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.canXOF = enableXOF;
    this.rounds = rounds;
    anumber(outputLen, "outputLen");
    if (!(0 < blockLen && blockLen < 200))
      throw new Error('"blockLen" must be 1..199');
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  clone() {
    return this._cloneInto();
  }
  keccak() {
    swap32IfBE(this.state32);
    keccakP(this.state32, this.rounds);
    swap32IfBE(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }
  update(data) {
    aexists(this);
    abytes2(data);
    const { blockLen, state, state32 } = this;
    const len = data.length;
    const canUseU32 = blockLen % 4 === 0 && data.byteOffset % 4 === 0;
    const blockLen32 = blockLen / 4;
    const data32 = canUseU32 && len >= blockLen ? u32(data) : void 0;
    for (let pos = 0; pos < len; ) {
      if (data32 !== void 0 && this.pos === 0 && pos % 4 === 0 && len - pos >= blockLen) {
        for (let i = 0, o = pos / 4; i < blockLen32; i++)
          state32[i] ^= data32[o + i];
        pos += blockLen;
        this.pos = blockLen;
        this.keccak();
        continue;
      }
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0; i < take; i++)
        state[this.pos++] ^= data[pos++];
      if (this.pos === blockLen)
        this.keccak();
    }
    return this;
  }
  finish() {
    if (this.finished)
      return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    state[pos] ^= suffix;
    if ((suffix & 128) !== 0 && pos === blockLen - 1)
      this.keccak();
    state[blockLen - 1] ^= 128;
    this.keccak();
  }
  writeInto(out) {
    aexists(this, false);
    abytes2(out);
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length; pos < len; ) {
      if (this.posOut >= blockLen)
        this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xofInto(out) {
    if (!this.enableXOF)
      throw new Error("XOF is not enabled");
    return this.writeInto(out);
  }
  xof(bytes) {
    anumber(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }
  digestInto(out) {
    aoutput(out, this);
    if (this.finished)
      throw new Error("digest() was already called");
    this.writeInto(out.length === this.outputLen ? out : out.subarray(0, this.outputLen));
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.outputLen);
    this.digestInto(out);
    return out;
  }
  destroy() {
    this.destroyed = true;
    clean(this.state);
  }
  _cloneInto(to) {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to ||= new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
    to.blockLen = blockLen;
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.canXOF = this.canXOF;
    to.destroyed = this.destroyed;
    return to;
  }
};
var genKeccak = (suffix, blockLen, outputLen, info = {}) => createHasher(() => new Keccak(blockLen, suffix, outputLen), info);
var keccak_256 = /* @__PURE__ */ genKeccak(1, 136, 32);

// src/attestation.ts
var TDX_BODY_OFFSET = 48;
var TD_ATTRIBUTES_OFFSET = TDX_BODY_OFFSET + 120;
var TD_ATTRIBUTES_LEN = 8;
var REPORT_DATA_OFFSET = TDX_BODY_OFFSET + 520;
var REPORT_DATA_LEN = 64;
var MIN_QUOTE_LEN = REPORT_DATA_OFFSET + REPORT_DATA_LEN;
var MEASUREMENT_LAYOUT = [
  ["mrSeam", 16],
  ["mrSignerSeam", 64],
  ["mrTd", 136],
  ["mrConfigId", 184],
  ["mrOwner", 232],
  ["mrOwnerConfig", 280],
  ["rtMr0", 328],
  ["rtMr1", 376],
  ["rtMr2", 424],
  ["rtMr3", 472]
];
var TDX_TEE_TYPE = 129;
function deriveEthAddress(pubKeyHex) {
  let hex = pubKeyHex.startsWith("0x") ? pubKeyHex.slice(2) : pubKeyHex;
  if (hex.length === 128) hex = "04" + hex;
  if (hex.length !== 130 || !hex.startsWith("04")) {
    throw new Error(
      `Invalid uncompressed secp256k1 public key (got ${hex.length} hex chars)`
    );
  }
  const keyBytes = fromHex(hex.slice(2));
  const hash = keccak_256(keyBytes);
  return hash.slice(12);
}
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
function decodeQuote(quote) {
  const value = quote.startsWith("0x") ? quote.slice(2) : quote;
  if (value.length % 2 === 0 && /^[0-9a-f]+$/i.test(value)) return fromHex(value);
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const binary = atob(padded);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    throw new Error("TDX quote is neither valid hex nor base64");
  }
}
function parseTdxQuote(quote) {
  const bytes = decodeQuote(quote);
  if (bytes.length < MIN_QUOTE_LEN) {
    throw new Error(
      `TDX quote too short: ${bytes.length} bytes (need >= ${MIN_QUOTE_LEN})`
    );
  }
  const teeType = bytes[4] | bytes[5] << 8 | bytes[6] << 16 | bytes[7] << 24;
  if (teeType !== TDX_TEE_TYPE) {
    throw new Error(
      `Not a TDX quote: teeType=0x${teeType.toString(16)} (expected 0x81)`
    );
  }
  return {
    bytes,
    tdAttributes: bytes.slice(TD_ATTRIBUTES_OFFSET, TD_ATTRIBUTES_OFFSET + TD_ATTRIBUTES_LEN),
    reportData: bytes.slice(REPORT_DATA_OFFSET, REPORT_DATA_OFFSET + REPORT_DATA_LEN),
    measurements: Object.fromEntries(
      MEASUREMENT_LAYOUT.map(([name, offset]) => [
        name,
        toHex(bytes.slice(TDX_BODY_OFFSET + offset, TDX_BODY_OFFSET + offset + 48))
      ])
    )
  };
}
function normalizeMeasurement(value) {
  return value.toLowerCase().replace(/^0x/, "");
}
function verifyMeasurements(actual, expected, errors) {
  let checked = 0;
  let matched = true;
  for (const [name, allowedValue] of Object.entries(expected)) {
    const allowed = (Array.isArray(allowedValue) ? allowedValue : [allowedValue]).map(normalizeMeasurement);
    checked += 1;
    if (!actual[name] || !allowed.includes(normalizeMeasurement(actual[name]))) {
      matched = false;
      errors.push(`TDX measurement mismatch: ${name}`);
    }
  }
  if (checked === 0) {
    errors.push("Expected measurement policy is empty");
    return false;
  }
  return matched;
}
async function verifyAttestation(response, clientNonce, verifierOrOptions) {
  const options = typeof verifierOrOptions === "function" ? { dcapVerifier: verifierOrOptions } : verifierOrOptions ?? {};
  const {
    dcapVerifier,
    requireDcap = false,
    gpuVerifier,
    requireGpu = false,
    expectedMeasurements,
    expectedModelId
  } = options;
  const errors = [];
  let nonceVerified = false;
  let signingKeyBound = false;
  let debugMode = false;
  let serverTdxValid = null;
  let serverVerified = response.verified ?? null;
  let dcap;
  let dcapVerified = false;
  let measurements;
  let measurementsVerified = null;
  let gpu;
  let gpuVerified = false;
  const result = () => ({
    nonceVerified,
    signingKeyBound,
    debugMode,
    serverTdxValid,
    serverVerified,
    dcap,
    dcapVerified,
    gpu,
    gpuVerified,
    measurements,
    measurementsVerified,
    verificationLevel: dcapVerified ? measurementsVerified === true ? "measured" : "dcap" : nonceVerified && signingKeyBound && !debugMode ? "binding" : "none",
    errors
  });
  if (clientNonce.length !== 32) {
    errors.push(`Invalid client nonce length: ${clientNonce.length} (expected 32)`);
    return result();
  }
  const clientNonceHex = toHex(clientNonce);
  if (response.nonce && normalizeMeasurement(response.nonce) !== clientNonceHex) {
    errors.push("Attestation response nonce does not match the requested nonce");
  }
  if (expectedModelId && response.model !== expectedModelId) {
    errors.push(`Attestation model mismatch: expected ${expectedModelId}, received ${response.model || "missing"}`);
  }
  if (response.verified === false) {
    errors.push("Venice reported that server-side attestation verification failed");
  }
  const signingKey = response.signing_key || response.signing_public_key;
  if (!signingKey) {
    errors.push("No signing key in attestation response");
    return result();
  }
  if (response.server_verification) {
    const sv = response.server_verification;
    serverTdxValid = sv.tdx?.valid ?? null;
    if (sv.tdx && !sv.tdx.valid) {
      errors.push(
        `Server TDX verification failed: ${sv.tdx.error || "unknown reason"}`
      );
    }
    if (sv.tdx?.signatureValid === false) {
      errors.push("Venice reported an invalid TDX quote signature");
    }
    if (sv.tdx?.certificateChainValid === false) {
      errors.push("Venice reported an invalid TDX certificate chain");
    }
    if (sv.tdx?.attestationKeyMatch === false) {
      errors.push("Venice reported a TDX attestation-key mismatch");
    }
    if (sv.nvidia && !sv.nvidia.valid) {
      errors.push(`Venice reported failed NVIDIA attestation: ${sv.nvidia.error || "unknown reason"}`);
    }
  }
  if (!response.intel_quote) {
    errors.push("No intel_quote in attestation response \u2014 cannot verify client-side");
    return result();
  }
  let reportData;
  let tdAttributes;
  let quoteBytes;
  try {
    ({ bytes: quoteBytes, reportData, tdAttributes, measurements } = parseTdxQuote(response.intel_quote));
  } catch (e) {
    errors.push(`Failed to parse TDX quote: ${e.message}`);
    return result();
  }
  debugMode = (tdAttributes[0] & 1) !== 0;
  if (debugMode) {
    errors.push("TEE is running in DEBUG mode \u2014 attestation cannot be trusted");
  }
  const nonceInReport = reportData.slice(32, 64);
  if (constantTimeEqual(nonceInReport, clientNonce)) {
    nonceVerified = true;
  } else {
    const hashInput = new ArrayBuffer(clientNonce.byteLength);
    new Uint8Array(hashInput).set(clientNonce);
    const hashedNonce = new Uint8Array(
      await crypto.subtle.digest("SHA-256", hashInput)
    );
    if (constantTimeEqual(nonceInReport, hashedNonce)) {
      nonceVerified = true;
    } else {
      errors.push(
        "Nonce verification failed: client nonce not found in REPORTDATA"
      );
    }
  }
  try {
    const expectedAddress = deriveEthAddress(signingKey);
    const addressInReport = reportData.slice(0, 20);
    signingKeyBound = constantTimeEqual(addressInReport, expectedAddress);
    if (!signingKeyBound) {
      errors.push(
        "Signing key not bound to TEE: Ethereum address mismatch in REPORTDATA"
      );
    }
  } catch (e) {
    errors.push(
      `Failed to verify signing key binding: ${e.message}`
    );
  }
  if (response.server_verification?.signingAddressBinding) {
    const sab = response.server_verification.signingAddressBinding;
    if (signingKeyBound !== sab.bound) {
      errors.push(
        `Signing key binding inconsistency: client=${signingKeyBound}, server=${sab.bound}`
      );
    }
  }
  if (response.server_verification?.nonceBinding) {
    const nb = response.server_verification.nonceBinding;
    if (nonceVerified !== nb.bound) {
      errors.push(
        `Nonce binding inconsistency: client=${nonceVerified}, server=${nb.bound}`
      );
    }
  }
  if (expectedMeasurements) {
    measurementsVerified = verifyMeasurements(measurements, expectedMeasurements, errors);
  }
  if (dcapVerifier) {
    try {
      dcap = await dcapVerifier(quoteBytes);
      const status = dcap.status;
      const acceptedStatuses = /* @__PURE__ */ new Set([
        "UpToDate",
        "SWHardeningNeeded",
        "ConfigurationNeeded",
        "ConfigurationAndSWHardeningNeeded"
      ]);
      if (acceptedStatuses.has(status)) {
        dcapVerified = true;
      } else {
        errors.push(`DCAP verification: unacceptable TCB status ${status || "Unknown"}`);
      }
    } catch (e) {
      errors.push(`DCAP verification failed: ${e.message}`);
    }
  }
  if (gpuVerifier && response.nvidia_payload) {
    const errorsBeforeGpu = errors.length;
    try {
      gpu = await gpuVerifier(response.nvidia_payload);
      if (!gpu.overallResult) {
        errors.push("NVIDIA did not vouch for the GPU evidence (overall attestation result false)");
      }
      if (gpu.eatNonce === null) {
        errors.push("NVIDIA attestation token carries no eat_nonce to bind it to this request");
      } else if (normalizeMeasurement(gpu.eatNonce) !== clientNonceHex) {
        errors.push(
          "NVIDIA attestation token eat_nonce does not match the nonce sent \u2014 the GPU evidence describes some other request"
        );
      }
      for (const [name, claims] of Object.entries(gpu.gpus)) {
        if (claims.debugStatus !== "disabled") {
          errors.push(
            `GPU ${name} did not assert debug mode disabled (dbgstat=${claims.debugStatus ?? "missing"})`
          );
        }
        if (claims.secureBoot !== true) {
          errors.push(
            `GPU ${name} did not assert secure boot enabled (secboot=${claims.secureBoot ?? "missing"})`
          );
        }
        if (claims.measurementResult !== "success") {
          errors.push(
            `GPU ${name} did not assert measurements matched NVIDIA's reference values (measres=${claims.measurementResult ?? "missing"})`
          );
        }
        if (claims.reportNonceMatch !== true) {
          errors.push(
            `GPU ${name} did not assert that its attestation report echoed the submitted nonce (nonce-match=${claims.reportNonceMatch ?? "missing"})`
          );
        }
        if (claims.eatNonce === null) {
          errors.push(`GPU ${name} token carries no eat_nonce to bind it to this request`);
        } else if (normalizeMeasurement(claims.eatNonce) !== clientNonceHex) {
          errors.push(`GPU ${name} token eat_nonce does not match the nonce sent`);
        }
      }
      if (Object.keys(gpu.gpus).length === 0) {
        errors.push("NVIDIA returned no per-GPU claims to check");
      }
      gpuVerified = errors.length === errorsBeforeGpu;
    } catch (e) {
      errors.push(`GPU attestation failed: ${e.message}`);
    }
  }
  if (requireGpu && !gpuVerified) {
    if (!gpuVerifier) {
      errors.push("GPU attestation is required but no gpuVerifier was provided");
    } else if (!response.nvidia_payload) {
      errors.push("GPU attestation is required but the response carried no GPU evidence");
    } else {
      errors.push("GPU attestation did not complete successfully");
    }
  }
  if (requireDcap && !dcapVerified) {
    errors.push(dcapVerifier ? "Full DCAP verification did not complete successfully" : "Full DCAP verification is required but no dcapVerifier was provided");
  }
  if (measurementsVerified === true && !dcapVerified) {
    errors.push("Measurement allowlist requires successful DCAP verification of the quote");
  }
  return result();
}

// node_modules/@noble/hashes/_md.js
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD = class {
  blockLen;
  outputLen;
  canXOF = false;
  padOffset;
  isLE;
  // For partial updates less than block size
  buffer;
  view;
  finished = false;
  length = 0;
  pos = 0;
  destroyed = false;
  constructor(blockLen, outputLen, padOffset, isLE2) {
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    abytes2(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    let processed = false;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        processed = true;
        continue;
      }
      buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
        processed = true;
      }
    }
    this.length += data.length;
    if (processed)
      this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    buffer.fill(0, pos);
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      buffer.fill(0);
    }
    setU64FromNum(view, blockLen - 8, this.length * 8, isLE2);
    this.process(view, 0);
    this.roundClean();
    const oview = out === buffer ? view : createView(out);
    const len = this.outputLen;
    const outLen = len / 4;
    const state = this.get();
    if (len % 4 || outLen > state.length)
      throw new Error("invalid outputLen");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneIntoMeta(to) {
    const { buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (pos)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);

// node_modules/@noble/hashes/sha2.js
var SHA256_K = /* @__PURE__ */ Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA2_32B = class extends HashMD {
  // We cannot use array here since array allows indexing by variable
  // which means optimizer/compiler cannot use registers.
  // Numeric initializers matter: starting the fields as `undefined` changes
  // V8's field representation and makes sha256 3x slower (measured).
  A = 0;
  B = 0;
  C = 0;
  D = 0;
  E = 0;
  F = 0;
  G = 0;
  H = 0;
  constructor(outputLen, IV) {
    super(64, outputLen, 8, false);
    this.A = IV[0] | 0;
    this.B = IV[1] | 0;
    this.C = IV[2] | 0;
    this.D = IV[3] | 0;
    this.E = IV[4] | 0;
    this.F = IV[5] | 0;
    this.G = IV[6] | 0;
    this.H = IV[7] | 0;
  }
  get() {
    const { A, B: B2, C: C2, D, E, F, G: G2, H } = this;
    return [A, B2, C2, D, E, F, G2, H];
  }
  // prettier-ignore
  set(A, B2, C2, D, E, F, G2, H) {
    this.A = A | 0;
    this.B = B2 | 0;
    this.C = C2 | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G2 | 0;
    this.H = H | 0;
  }
  _cloneInto(to) {
    (to ||= new this.constructor()).set(...this.get());
    return this._cloneIntoMeta(to);
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B: B2, C: C2, D, E, F, G: G2, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G2) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B2, C2) | 0;
      H = G2;
      G2 = F;
      F = E;
      E = D + T1 | 0;
      D = C2;
      C2 = B2;
      B2 = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B2 = B2 + this.B | 0;
    C2 = C2 + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G2 = G2 + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B2, C2, D, E, F, G2, H);
  }
  roundClean() {
    clean(SHA256_W);
  }
  destroy() {
    this.destroyed = true;
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
  }
};
var _SHA256 = class extends SHA2_32B {
  constructor() {
    super(32, SHA256_IV);
  }
};
var sha256 = /* @__PURE__ */ createHasher(
  () => new _SHA256(),
  /* @__PURE__ */ oidNist(1)
);

// src/receipt.ts
var BODY_BINDING_CHECKS = [
  "request_body_hash_matches",
  "response_body_hash_matches"
];
function jcsStringify(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new TypeError(`JCS: ACI restricts numbers to integers, got ${value}`);
    }
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (typeof value !== "object") {
    throw new TypeError(`JCS: unsupported type ${typeof value}`);
  }
  if (Array.isArray(value)) return `[${value.map((item) => jcsStringify(item)).join(",")}]`;
  const entries = Object.keys(value).filter((key) => value[key] !== void 0).sort().map((key) => `${JSON.stringify(key)}:${jcsStringify(value[key])}`);
  return `{${entries.join(",")}}`;
}
function sha256Prefixed(text) {
  return hashReceiptBody(text);
}
function hashReceiptBody(body) {
  if (typeof body !== "string" && !(body instanceof Uint8Array)) {
    throw new TypeError("Receipt body must be a string or Uint8Array");
  }
  const bytes = typeof body === "string" ? new TextEncoder().encode(body) : body;
  return `sha256:${toHex(sha256(bytes))}`;
}
function computeWorkloadId(publicKey) {
  return sha256Prefixed(
    jcsStringify({ algo: publicKey.algo, public_key: publicKey.public_key })
  );
}
function computeWorkloadKeysetDigest(keyset) {
  return sha256Prefixed(jcsStringify(keyset));
}
function receiptSigningBytes(receipt) {
  const { value: _omitted, ...signatureWithoutValue } = receipt.signature;
  const forSigning = {
    ...receipt,
    signature: signatureWithoutValue
  };
  return new TextEncoder().encode(jcsStringify(forSigning));
}
function fromHexBytes(hex) {
  const clean2 = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean2.length === 0 || clean2.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(clean2)) {
    throw new TypeError("Expected non-empty, even-length hexadecimal bytes");
  }
  const out = new Uint8Array(clean2.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean2.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
async function verifyEd25519(publicKey, signature, message) {
  const key = await crypto.subtle.importKey("raw", publicKey, "Ed25519", false, [
    "verify"
  ]);
  return crypto.subtle.verify(
    "Ed25519",
    key,
    signature,
    message
  );
}
function recoverReceiptSigner(text, signatureHex) {
  const clean2 = signatureHex.startsWith("0x") ? signatureHex.slice(2) : signatureHex;
  if (clean2.length !== 130 || !/^[0-9a-f]+$/i.test(clean2)) {
    throw new TypeError("Receipt signature must be 65 recoverable bytes of hex");
  }
  let recovery = Number.parseInt(clean2.slice(128, 130), 16);
  if (recovery >= 27 && recovery <= 30) recovery -= 27;
  if (recovery !== 0 && recovery !== 1) {
    throw new TypeError(`Unsupported recovery id ${clean2.slice(128, 130)}`);
  }
  const message = new TextEncoder().encode(text);
  const prefix = new TextEncoder().encode(`Ethereum Signed Message:
${message.length}`);
  const digest = keccak_256(new Uint8Array([...prefix, ...message]));
  const signature = new Signature(
    BigInt(`0x${clean2.slice(0, 64)}`),
    BigInt(`0x${clean2.slice(64, 128)}`),
    recovery
  );
  const publicKey = signature.recoverPublicKey(digest).toRawBytes(false);
  return `0x${toHex(deriveEthAddress(toHex(publicKey)))}`;
}
function signedTextForReceipt(receipt, responseHashField) {
  const request = exactlyOneEvent(receipt, "request.received")?.body_hash;
  const response = exactlyOneEvent(receipt, "response.returned")?.[responseHashField];
  if (typeof request !== "string" || typeof response !== "string") return null;
  const strip = (hash) => hash.replace(/^sha256:/, "");
  return `${strip(request)}:${strip(response)}`;
}
function exactlyOneEvent(receipt, type) {
  const matches = receipt.event_log.filter(
    (event) => event && typeof event === "object" && event.type === type
  );
  return matches.length === 1 ? matches[0] : void 0;
}
function isReceiptBody(value) {
  return typeof value === "string" || value instanceof Uint8Array;
}
async function verifyReceipt(signatureResponse, attestation, options) {
  const checks = [];
  const add = (name, ok, detail) => {
    checks.push(detail === void 0 ? { name, ok } : { name, ok, detail });
  };
  const receipt = signatureResponse?.receipt;
  if (!receipt || !receipt.signature || !Array.isArray(receipt.event_log)) {
    add("receipt_present", false, "signature response carried no complete receipt");
    return { verified: false, checks };
  }
  if (!options || typeof options !== "object") {
    add("verification_context_present", false, "trust anchor and request/response context required");
    return { verified: false, checks };
  }
  const { trustAnchor, requestId, requestBody, responseBody, responseHashField } = options;
  const contextComplete = Boolean(
    trustAnchor?.workloadId && trustAnchor?.workloadKeysetDigest && requestId && isReceiptBody(requestBody) && isReceiptBody(responseBody) && (responseHashField === "wire_hash" || responseHashField === "cleartext_hash")
  );
  add(
    "verification_context_present",
    contextComplete,
    contextComplete ? void 0 : "trustAnchor, requestId, requestBody, responseBody, and responseHashField are required"
  );
  if (!contextComplete) return { verified: false, checks };
  const unsupportedVersions = [
    receipt.api_version === "aci/1" ? void 0 : `receipt "${receipt.api_version}"`,
    signatureResponse.api_version === void 0 || signatureResponse.api_version === "aci/1" ? void 0 : `signature response "${signatureResponse.api_version}"`,
    attestation?.api_version === void 0 || attestation.api_version === "aci/1" ? void 0 : `attestation "${attestation.api_version}"`
  ].filter((value) => value !== void 0);
  add(
    "api_version_supported",
    unsupportedVersions.length === 0,
    unsupportedVersions.length === 0 ? void 0 : `unsupported api_version: ${unsupportedVersions.join(", ")}`
  );
  const keyset = attestation?.attestation?.workload_keyset;
  if (!keyset) {
    add("keyset_present", false, "attestation carried no workload_keyset");
    return { verified: false, checks };
  }
  const identityKey = keyset.workload_identity?.public_key;
  const signingKeys = keyset.receipt_signing_keys;
  const keysetShapeValid = Boolean(
    identityKey && typeof identityKey.algo === "string" && typeof identityKey.public_key === "string" && Array.isArray(signingKeys) && signingKeys.every(
      (key) => key && typeof key === "object" && typeof key.key_id === "string" && typeof key.algo === "string" && typeof key.public_key === "string"
    )
  );
  if (!keysetShapeValid) {
    add("keyset_well_formed", false, "workload identity or receipt signing keys are malformed");
    return { verified: false, checks };
  }
  let keysetDigest;
  let workloadId;
  try {
    keysetDigest = computeWorkloadKeysetDigest(keyset);
    workloadId = computeWorkloadId(identityKey);
  } catch (error) {
    add(
      "keyset_well_formed",
      false,
      `invalid workload keyset: ${error instanceof Error ? error.message : String(error)}`
    );
    return { verified: false, checks };
  }
  add("keyset_well_formed", true);
  add(
    "keyset_digest_matches_trust_anchor",
    keysetDigest === trustAnchor.workloadKeysetDigest,
    keysetDigest === trustAnchor.workloadKeysetDigest ? void 0 : `computed ${keysetDigest}, trusted ${trustAnchor.workloadKeysetDigest}`
  );
  add(
    "attestation_keyset_digest_matches_trust_anchor",
    attestation.workload_keyset_digest === trustAnchor.workloadKeysetDigest,
    attestation.workload_keyset_digest === trustAnchor.workloadKeysetDigest ? void 0 : `attestation says ${attestation.workload_keyset_digest ?? "missing"}`
  );
  add(
    "receipt_keyset_digest_matches_trust_anchor",
    receipt.workload_keyset_digest === trustAnchor.workloadKeysetDigest,
    receipt.workload_keyset_digest === trustAnchor.workloadKeysetDigest ? void 0 : `receipt says ${receipt.workload_keyset_digest}`
  );
  add(
    "workload_id_matches_trust_anchor",
    workloadId === trustAnchor.workloadId && attestation.workload_id === trustAnchor.workloadId && receipt.workload_id === trustAnchor.workloadId,
    workloadId === trustAnchor.workloadId && attestation.workload_id === trustAnchor.workloadId && receipt.workload_id === trustAnchor.workloadId ? void 0 : `computed ${workloadId}, attestation ${attestation.workload_id ?? "missing"}, receipt ${receipt.workload_id ?? "missing"}, trusted ${trustAnchor.workloadId}`
  );
  const entry = signingKeys.find(
    (key) => key.key_id === receipt.signature.key_id
  );
  add(
    "key_in_trusted_keyset",
    Boolean(entry),
    entry ? void 0 : `key_id "${receipt.signature.key_id}" is not in receipt_signing_keys`
  );
  if (entry) {
    const algoMatches = entry.algo === receipt.signature.algo;
    add(
      "key_algo_matches",
      algoMatches,
      algoMatches ? void 0 : `receipt says ${receipt.signature.algo}, keyset says ${entry.algo}`
    );
    if (algoMatches && entry.algo === "ed25519") {
      try {
        const ok = await verifyEd25519(
          fromHexBytes(entry.public_key),
          fromHexBytes(receipt.signature.value),
          receiptSigningBytes(receipt)
        );
        add("receipt_signature", ok, ok ? void 0 : "Ed25519 verification failed");
      } catch (error) {
        add(
          "receipt_signature",
          false,
          `Ed25519 unavailable or input rejected: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    } else if (algoMatches) {
      add("receipt_signature", false, `unsupported receipt signing algorithm "${entry.algo}"`);
    }
  }
  add(
    "chat_id_matches_request",
    receipt.chat_id === requestId,
    receipt.chat_id === requestId ? void 0 : `receipt is for ${receipt.chat_id}, expected ${requestId}`
  );
  const requestEvent = exactlyOneEvent(receipt, "request.received");
  const requestHash = hashReceiptBody(requestBody);
  add(
    "request_body_hash_matches",
    requestEvent?.body_hash === requestHash,
    requestEvent?.body_hash === requestHash ? void 0 : `computed ${requestHash}, receipt says ${requestEvent?.body_hash ?? "missing or ambiguous event"}`
  );
  const responseEvent = exactlyOneEvent(receipt, "response.returned");
  const responseHash = hashReceiptBody(responseBody);
  const receiptResponseHash = responseEvent?.[responseHashField];
  add(
    "response_body_hash_matches",
    receiptResponseHash === responseHash,
    receiptResponseHash === responseHash ? void 0 : `computed ${responseHash}, receipt ${responseHashField} says ${typeof receiptResponseHash === "string" ? receiptResponseHash : "missing or ambiguous event"}`
  );
  const rawAttestationAddress = attestation.signing_address;
  const rawSignatureAddress = signatureResponse.signing_address;
  const attestationAddress = typeof rawAttestationAddress === "string" ? rawAttestationAddress.toLowerCase() : void 0;
  const signatureAddress = typeof rawSignatureAddress === "string" ? rawSignatureAddress.toLowerCase() : void 0;
  if (rawAttestationAddress !== void 0 || rawSignatureAddress !== void 0) {
    add(
      "signing_address_cross_check",
      Boolean(attestationAddress && signatureAddress && attestationAddress === signatureAddress),
      attestationAddress && signatureAddress && attestationAddress === signatureAddress ? void 0 : `${signatureAddress ?? "missing"} vs attestation ${attestationAddress ?? "missing"}`
    );
  }
  const signedText = signatureResponse.text;
  const topLevelSignature = signatureResponse.signature;
  if (signedText !== void 0 || topLevelSignature !== void 0) {
    const complete = typeof signedText === "string" && typeof topLevelSignature === "string";
    add(
      "top_level_signature_complete",
      complete,
      complete ? void 0 : "top-level receipt signature requires both text and signature strings"
    );
    if (!complete) {
      return { verified: false, checks };
    }
    const expectedText = signedTextForReceipt(receipt, responseHashField);
    add(
      "signed_text_matches_receipt_hashes",
      expectedText !== null && expectedText === signedText,
      expectedText === null ? "receipt has no unambiguous request/response hash pair to compare" : expectedText === signedText ? void 0 : `signature covers "${signedText}", receipt hashes give "${expectedText}"`
    );
    if (!attestationAddress) {
      add(
        "signature_recovers_to_attested_key",
        false,
        "attestation carried no signing address to compare with the recovered signer"
      );
    } else {
      try {
        const recovered = recoverReceiptSigner(signedText, topLevelSignature).toLowerCase();
        add(
          "signature_recovers_to_attested_key",
          recovered === attestationAddress,
          recovered === attestationAddress ? void 0 : `recovered ${recovered}, attestation binds ${attestationAddress}`
        );
      } catch (error) {
        add(
          "signature_recovers_to_attested_key",
          false,
          error instanceof Error ? error.message : String(error)
        );
      }
    }
  }
  return { verified: checks.length > 0 && checks.every((check) => check.ok), checks };
}

// src/url.ts
function stripTrailingSlashes(value) {
  let end = value.length;
  while (end > 0 && value[end - 1] === "/") end--;
  return value.slice(0, end);
}

// src/aci.ts
var ACI_REPORT_DATA_PURPOSE = "aci.report_data.v1";
var ACI_KEYSET_ENDORSEMENT_PURPOSE = "aci.keyset.endorsement.v1";
var ACI_ATTESTATION_PATH = "/v1/aci/attestation";
function aciReportDataStatement(workloadId, workloadKeysetDigest, nonce) {
  return new TextEncoder().encode(
    jcsStringify({
      purpose: ACI_REPORT_DATA_PURPOSE,
      workload_id: workloadId,
      workload_keyset_digest: workloadKeysetDigest,
      nonce
    })
  );
}
function aciReportData(workloadId, workloadKeysetDigest, nonce) {
  return sha256(aciReportDataStatement(workloadId, workloadKeysetDigest, nonce));
}
function aciKeysetEndorsementPayload(workloadKeysetDigest) {
  return new TextEncoder().encode(
    jcsStringify({
      purpose: ACI_KEYSET_ENDORSEMENT_PURPOSE,
      workload_keyset_digest: workloadKeysetDigest
    })
  );
}
function constantTimeEqual2(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
async function fetchAciAttestation(baseUrl, nonce, fetchImpl = fetch) {
  const url = `${stripTrailingSlashes(baseUrl)}${ACI_ATTESTATION_PATH}?nonce=${encodeURIComponent(nonce)}`;
  const res = await fetchImpl(url);
  if (!res.ok) {
    throw new Error(`ACI attestation fetch failed (${res.status}) from ${baseUrl}`);
  }
  return await res.json();
}
function generateAciNonce() {
  return toHex(crypto.getRandomValues(new Uint8Array(32)));
}
async function verifyAciAttestation(report, nonce, options = {}) {
  return runAciChecks(report, nonce, options);
}
async function verifyRelayedAciAttestation(report, options = {}) {
  const result = await runAciChecks(report, void 0, options);
  return { ...result, anchor: null };
}
async function runAciChecks(report, nonce, options = {}) {
  const {
    dcapVerifier,
    requireDcap = true,
    expectedMeasurements,
    clockSkewSeconds = 60,
    now = () => Math.floor(Date.now() / 1e3)
  } = options;
  const checks = [];
  const add = (name, ok, detail) => {
    checks.push(detail === void 0 ? { name, ok } : { name, ok, detail });
  };
  let measurements;
  let dcap;
  const attestation = report?.attestation;
  const keyset = attestation?.workload_keyset;
  const quote = attestation?.evidence?.quote;
  const workloadId = report?.workload_id;
  const keysetDigest = report?.workload_keyset_digest;
  const staleAfter = attestation?.freshness?.stale_after ?? null;
  const sourceCommit = attestation?.source_provenance?.repo_commit ?? null;
  let nonceBound = false;
  const fail = () => ({
    verified: false,
    nonceBound,
    anchor: null,
    checks,
    measurements,
    dcap,
    staleAfter,
    sourceCommit
  });
  if (!keyset || !quote || !workloadId || !keysetDigest) {
    add(
      "report_well_formed",
      false,
      "report needs workload_id, workload_keyset_digest, attestation.workload_keyset and evidence.quote"
    );
    return fail();
  }
  add("report_well_formed", true);
  add(
    "api_version_supported",
    report.api_version === void 0 || report.api_version === "aci/1",
    report.api_version === void 0 || report.api_version === "aci/1" ? void 0 : `unsupported api_version "${report.api_version}"`
  );
  let computedDigest;
  let computedWorkloadId;
  try {
    computedDigest = computeWorkloadKeysetDigest(keyset);
    computedWorkloadId = computeWorkloadId(keyset.workload_identity.public_key);
  } catch (error) {
    add(
      "keyset_recomputes",
      false,
      `could not canonicalize keyset: ${error instanceof Error ? error.message : String(error)}`
    );
    return fail();
  }
  add(
    "keyset_digest_recomputes",
    computedDigest === keysetDigest,
    computedDigest === keysetDigest ? void 0 : `computed ${computedDigest}, report says ${keysetDigest}`
  );
  add(
    "workload_id_recomputes",
    computedWorkloadId === workloadId,
    computedWorkloadId === workloadId ? void 0 : `computed ${computedWorkloadId}, report says ${workloadId}`
  );
  let reportData;
  let tdAttributes;
  let quoteBytes;
  try {
    ({ bytes: quoteBytes, reportData, tdAttributes, measurements } = parseTdxQuote(quote));
  } catch (error) {
    add("quote_parsed", false, error instanceof Error ? error.message : String(error));
    return fail();
  }
  add("quote_parsed", true);
  const debugMode = (tdAttributes[0] & 1) !== 0;
  add(
    "debug_mode_disabled",
    !debugMode,
    debugMode ? "TD is running in DEBUG mode \u2014 its measurements mean nothing" : void 0
  );
  if (nonce !== void 0) {
    const expectedReportData = aciReportData(workloadId, keysetDigest, nonce);
    nonceBound = constantTimeEqual2(reportData.slice(0, 32), expectedReportData);
    add(
      "report_data_binds_keyset_and_nonce",
      nonceBound,
      nonceBound ? void 0 : `quote REPORTDATA starts ${toHex(reportData.slice(0, 32))}, statement hashes to ${toHex(expectedReportData)}`
    );
  } else {
    add(
      "report_data_binds_keyset_and_nonce",
      false,
      "the nonce used for this relayed report was not published, so its keyset cannot be bound to REPORTDATA"
    );
  }
  const tailClear = reportData.slice(32, 64).every((byte) => byte === 0);
  add(
    "report_data_tail_unused",
    tailClear,
    tailClear ? void 0 : `expected 32 zero bytes, got ${toHex(reportData.slice(32, 64))}`
  );
  const servedReportData = attestation?.report_data;
  if (typeof servedReportData === "string") {
    const matches = servedReportData.toLowerCase().replace(/^0x/, "") === toHex(reportData.slice(0, 32));
    add(
      "served_report_data_matches_quote",
      matches,
      matches ? void 0 : `report says ${servedReportData}, quote says ${toHex(reportData.slice(0, 32))}`
    );
  }
  const endorsement = attestation?.keyset_endorsement;
  if (endorsement) {
    if (endorsement.algo !== "ecdsa-secp256k1") {
      add("keyset_endorsement", false, `unsupported endorsement algo "${endorsement.algo}"`);
    } else {
      try {
        const payloadHash = sha256(aciKeysetEndorsementPayload(keysetDigest));
        const ok = verify(
          fromHex(endorsement.value),
          payloadHash,
          keyset.workload_identity.public_key.public_key,
          { lowS: false }
        );
        add("keyset_endorsement", ok, ok ? void 0 : "identity key did not endorse this keyset digest");
      } catch (error) {
        add(
          "keyset_endorsement",
          false,
          `endorsement check failed: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }
  }
  if (staleAfter !== null) {
    const fresh = now() <= staleAfter + clockSkewSeconds;
    add(
      "report_fresh",
      fresh,
      fresh ? void 0 : `report went stale at ${new Date(staleAfter * 1e3).toISOString()}`
    );
  }
  if (dcapVerifier) {
    try {
      dcap = await dcapVerifier(quoteBytes);
      const accepted = /* @__PURE__ */ new Set([
        "UpToDate",
        "SWHardeningNeeded",
        "ConfigurationNeeded",
        "ConfigurationAndSWHardeningNeeded"
      ]);
      const ok = accepted.has(dcap.status);
      add("dcap_verified", ok, ok ? void 0 : `unacceptable TCB status ${dcap.status || "Unknown"}`);
    } catch (error) {
      add("dcap_verified", false, error instanceof Error ? error.message : String(error));
    }
  } else if (requireDcap) {
    add(
      "dcap_verified",
      false,
      "no dcapVerifier supplied \u2014 the anchor would rest on an unverified quote"
    );
  }
  if (expectedMeasurements && measurements) {
    const entries = Object.entries(expectedMeasurements);
    if (entries.length === 0) {
      add("measurements_allowed", false, "expected measurement policy is empty");
    } else {
      const normalize = (value) => value.toLowerCase().replace(/^0x/, "");
      const mismatched = entries.filter(([name, allowed]) => {
        const values = (Array.isArray(allowed) ? allowed : [allowed]).map(normalize);
        return !measurements[name] || !values.includes(normalize(measurements[name]));
      }).map(([name]) => name);
      add(
        "measurements_allowed",
        mismatched.length === 0,
        mismatched.length === 0 ? void 0 : `mismatched: ${mismatched.join(", ")}`
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
    sourceCommit
  };
}
async function establishAciTrustAnchor(baseUrl, options = {}) {
  const { fetchImpl, ...verifyOptions } = options;
  const nonce = generateAciNonce();
  const report = await fetchAciAttestation(baseUrl, nonce, fetchImpl ?? fetch);
  return verifyAciAttestation(report, nonce, verifyOptions);
}

// src/session.ts
var ACI_SESSIONS_PATH = "/v1/aci/sessions";
function computeAttestedSessionId(session) {
  const material = {
    upstream_name: session.upstream_name,
    endpoint: session.endpoint ?? null,
    verifier_id: session.verifier_id,
    identity: session.identity ?? null,
    channel_binding: session.channel_binding,
    claims: session.claims,
    evidence_digest: session.evidence?.digest ?? null
  };
  return `as_${toHex(sha256(new TextEncoder().encode(jcsStringify(material))))}`;
}
async function fetchAttestedSession(baseUrl, sessionId, fetchImpl = fetch) {
  const url = `${stripTrailingSlashes(baseUrl)}${ACI_SESSIONS_PATH}/${encodeURIComponent(sessionId)}`;
  const res = await fetchImpl(url);
  if (!res.ok) {
    throw new Error(
      res.status === 404 ? `attested session ${sessionId} is not in the store (expired, or never existed)` : `attested session fetch failed (${res.status}) from ${baseUrl}`
    );
  }
  return await res.json();
}
function decodeSessionEvidence(session) {
  const data = session.evidence?.data;
  if (typeof data !== "string") return null;
  const comma = data.indexOf(",");
  if (!data.startsWith("data:") || comma < 0) {
    throw new TypeError("session evidence is not a valid data URI");
  }
  const metadata = data.slice("data:".length, comma).toLowerCase().split(";");
  if (!metadata.includes("base64")) {
    throw new TypeError("session evidence data URI must use base64 encoding");
  }
  const payload = data.slice(comma + 1);
  const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[a-z0-9+/]*={0,2}$/i.test(normalized) || normalized.length % 4 === 1) {
    throw new TypeError("session evidence contains invalid base64");
  }
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new TypeError("session evidence contains invalid base64");
  }
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  let report;
  try {
    report = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new TypeError("session evidence is not valid UTF-8 JSON");
  }
  if (!report || typeof report !== "object" || Array.isArray(report)) {
    throw new TypeError("session evidence JSON must contain an object");
  }
  return { bytes, report };
}
function originHost(value) {
  if (!value) return null;
  try {
    return new URL(value).host.toLowerCase();
  } catch {
    return null;
  }
}
async function verifyAttestedSession(session, options) {
  const checks = [];
  const add = (name, ok, detail) => {
    checks.push(detail === void 0 ? { name, ok } : { name, ok, detail });
  };
  const unknownClaims = Object.entries(session?.claims ?? {}).filter(([, claim]) => claim?.status === "unknown").map(([name]) => name);
  const done = (upstream2) => ({
    verified: checks.every((check) => check.ok),
    checks,
    upstream: upstream2,
    upstreamNonceBound: upstream2?.nonceBound ?? false,
    unknownClaims
  });
  if (!session || typeof session.session_id !== "string" || !Array.isArray(session.channel_binding)) {
    add("session_well_formed", false, "session record is missing session_id or channel_binding");
    return done(null);
  }
  add("session_well_formed", true);
  let recomputed;
  try {
    recomputed = computeAttestedSessionId(session);
  } catch (error) {
    add(
      "session_id_recomputes",
      false,
      `could not canonicalize session: ${error instanceof Error ? error.message : String(error)}`
    );
    return done(null);
  }
  add(
    "session_id_recomputes",
    recomputed === session.session_id,
    recomputed === session.session_id ? void 0 : `computed ${recomputed}, record says ${session.session_id}`
  );
  add(
    "session_id_matches_receipt",
    session.session_id === options.expectedSessionId,
    session.session_id === options.expectedSessionId ? void 0 : `record is ${session.session_id}, receipt named ${options.expectedSessionId}`
  );
  if (options.expectedOrigin) {
    const matches = originHost(session.endpoint) === originHost(options.expectedOrigin);
    add(
      "endpoint_matches_receipt_origin",
      matches,
      matches ? void 0 : `session endpoint ${session.endpoint ?? "missing"}, receipt named ${options.expectedOrigin}`
    );
  }
  const now = options.now ?? (() => Math.floor(Date.now() / 1e3));
  if (typeof session.expires_at === "number") {
    const live = now() <= session.expires_at + (options.clockSkewSeconds ?? 60);
    add("session_within_retention", live, live ? void 0 : "session record is past its retention deadline");
  }
  if (options.skipEvidence) return done(null);
  if (typeof session.evidence?.data !== "string") {
    add(
      "evidence_present",
      false,
      "session carries no inline evidence \u2014 fetch it by id rather than from the list"
    );
    return done(null);
  }
  add("evidence_present", true);
  let evidence;
  try {
    evidence = decodeSessionEvidence(session);
    add("evidence_decodes", true);
  } catch (error) {
    add(
      "evidence_decodes",
      false,
      error instanceof Error ? error.message : String(error)
    );
    return done(null);
  }
  const digest = `sha256:${toHex(sha256(evidence.bytes))}`;
  const digestOk = digest === session.evidence?.digest;
  add(
    "evidence_digest_matches",
    digestOk,
    digestOk ? void 0 : `computed ${digest}, session says ${session.evidence?.digest ?? "missing"}`
  );
  if (!options.dcapVerifier) {
    add("upstream_report_verified", false, "no dcapVerifier supplied \u2014 the upstream quote was not checked");
    return done(null);
  }
  const upstream = await verifyRelayedAciAttestation(evidence.report, {
    dcapVerifier: options.dcapVerifier,
    clockSkewSeconds: options.clockSkewSeconds,
    now: options.now
  });
  for (const check of upstream.checks) {
    checks.push({ ...check, name: `upstream.${check.name}` });
  }
  const keysetQuoteBound = upstream.checks.some(
    (check) => check.name === "report_data_binds_keyset_and_nonce" && check.ok
  );
  if (!keysetQuoteBound) {
    add(
      "channel_binding_in_attested_keyset",
      false,
      "upstream keyset is not quote-bound because the report nonce was not published"
    );
    return done(upstream);
  }
  const tlsKeys = evidence.report.attestation?.workload_keyset?.tls_public_keys;
  const bindings = session.channel_binding.filter((b) => b.type === "tls_spki_sha256");
  if (bindings.length === 0) {
    add("channel_binding_present", false, "session records no TLS channel binding");
  } else if (!Array.isArray(tlsKeys)) {
    add("channel_binding_in_attested_keyset", false, "upstream keyset publishes no TLS keys");
  } else {
    const unmatched = bindings.filter(
      (binding) => !tlsKeys.some(
        (key) => key.spki_sha256?.toLowerCase() === binding.spki_sha256?.toLowerCase() && (originHost(binding.origin) === null || key.domain?.toLowerCase() === originHost(binding.origin))
      )
    );
    add(
      "channel_binding_in_attested_keyset",
      unmatched.length === 0,
      unmatched.length === 0 ? void 0 : `no attested TLS key for ${unmatched.map((b) => `${b.origin ?? "?"}/${b.spki_sha256 ?? "?"}`).join(", ")}`
    );
  }
  return done(upstream);
}

// node_modules/@noble/curves/utils.js
function aarray(item, title, inner = () => {
}) {
  if (!Array.isArray(item))
    throw new TypeError(`"${title}" expected array, got type=${typeof item}`);
  for (let i = 0; i < item.length; i++)
    inner(item[i], `${title}[${i}]`);
  return item;
}
var abytes3 = (value, length, title) => abytes2(value, length, title);
var anumber2 = anumber;
function aobject2(value, title = "object") {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError(title === "object" ? "expected valid options object" : `"${title}" expected object, got type=${typeof value}`);
  return value;
}
function afunction(value, title) {
  if (typeof value !== "function")
    throw new TypeError(`"${title}" is invalid: expected function, got ${typeof value}`);
  return value;
}
var bytesToHex3 = bytesToHex2;
var hexToBytes3 = (hex) => hexToBytes2(hex);
var isBytes3 = isBytes2;
var randomBytes3 = (bytesLength) => randomBytes2(bytesLength);
var _0n2 = /* @__PURE__ */ BigInt(0);
var _1n2 = /* @__PURE__ */ BigInt(1);
var atitle2 = (title) => title ? `"${title}" ` : "";
function abool2(value, title = "") {
  if (typeof value !== "boolean")
    throw new TypeError(atitle2(title) + "expected boolean, got type=" + typeof value);
  return value;
}
function abignumber(n) {
  if (typeof n === "bigint") {
    if (!isPosBig(n))
      throw new RangeError("positive bigint expected, got " + n);
  } else
    anumber2(n);
  return n;
}
function asafenumber(value, title = "") {
  if (typeof value !== "number") {
    const prefix = title && `"${title}" `;
    throw new TypeError(prefix + "expected number, got type=" + typeof value);
  }
  if (!Number.isSafeInteger(value)) {
    const prefix = title && `"${title}" `;
    throw new RangeError(prefix + "expected safe integer, got " + value);
  }
}
function hexToNumber(hex) {
  if (typeof hex !== "string")
    throw new TypeError("hex string expected, got " + typeof hex);
  return hex === "" ? _0n2 : BigInt("0x" + hex);
}
function bytesToNumberBE(bytes) {
  return hexToNumber(bytesToHex2(bytes));
}
function bytesToNumberLE(bytes) {
  return hexToNumber(bytesToHex2(copyBytes(abytes2(bytes)).reverse()));
}
function numberToBytesBE(n, len) {
  anumber(len);
  if (len === 0)
    throw new Error("zero output length is invalid");
  n = abignumber(n);
  const expectedLen = len * 2;
  const hex = n.toString(16);
  if (hex.length > expectedLen)
    throw new RangeError("number is too large");
  return hexToBytes2(hex.padStart(expectedLen, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function copyBytes(bytes) {
  return Uint8Array.from(abytes3(bytes));
}
function isPosBig(n) {
  return typeof n === "bigint" && _0n2 <= n;
}
function inRange(n, min, max) {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}
function aInRange(title, n, min, max) {
  if (!inRange(n, min, max))
    throw new RangeError("expected valid " + title + ": " + min + " <= n < " + max + ", got " + n);
}
function bitLen(n) {
  if (n < _0n2)
    throw new Error("expected non-negative bigint, got " + n);
  return n === _0n2 ? 0 : n.toString(2).length;
}
var bitMask = (n) => {
  asafenumber(n, "n");
  return (_1n2 << BigInt(n)) - _1n2;
};
function validateObject(object, fields = {}, optFields = {}, title = "object") {
  aobject2(object, title);
  aobject2(fields, "fields");
  aobject2(optFields, "optFields");
  function checkField(fieldName, expectedType, isOpt) {
    const label = title === "object" ? `param "${String(fieldName)}"` : `"${title}.${String(fieldName)}"`;
    const val = object[fieldName];
    if (!Object.hasOwn(object, fieldName) && (isOpt ? val !== void 0 : expectedType !== "function")) {
      throw new TypeError(`${label} is invalid: expected own property`);
    }
    if (isOpt && val === void 0)
      return;
    const current = typeof val;
    if (current !== expectedType || val === null)
      throw new TypeError(`${label} is invalid: expected ${expectedType}, got ${current}`);
  }
  const iter = (f, isOpt) => Object.entries(f).forEach(([k, v]) => checkField(k, v, isOpt));
  iter(fields, false);
  iter(optFields, true);
}

// node_modules/@noble/curves/abstract/modular.js
var _0n3 = /* @__PURE__ */ BigInt(0);
var _1n3 = /* @__PURE__ */ BigInt(1);
var _2n2 = /* @__PURE__ */ BigInt(2);
var _3n = /* @__PURE__ */ BigInt(3);
var _4n = /* @__PURE__ */ BigInt(4);
var _5n = /* @__PURE__ */ BigInt(5);
var _7n2 = /* @__PURE__ */ BigInt(7);
var _8n = /* @__PURE__ */ BigInt(8);
var _9n = /* @__PURE__ */ BigInt(9);
var _15n = /* @__PURE__ */ BigInt(15);
var _16n = /* @__PURE__ */ BigInt(16);
var POW_WINDOWED_MIN = /* @__PURE__ */ BigInt("0x10000000000000000");
function mod(a, b) {
  if (b <= _0n3)
    throw new Error("mod: expected positive modulus, got " + b);
  const result = a % b;
  return result >= _0n3 ? result : b + result;
}
function pow(num, power, modulo) {
  if (modulo <= _1n3)
    throw new Error("pow: expected modulus > 1, got " + modulo);
  if (typeof power !== "bigint")
    throw new TypeError("invalid exponent: expected bigint, got " + typeof power);
  if (power < _0n3)
    throw new Error("invalid exponent, negatives unsupported");
  if (power === _0n3)
    return _1n3;
  if (power === _1n3)
    return num;
  let d = num % modulo;
  if (d < _0n3)
    d += modulo;
  if (power < POW_WINDOWED_MIN) {
    let p2 = _1n3;
    while (power > _0n3) {
      if (power & _1n3)
        p2 = p2 * d % modulo;
      d = d * d % modulo;
      power >>= _1n3;
    }
    return p2;
  }
  const digits = [];
  while (power > _0n3) {
    digits.push(Number(power & _15n));
    power >>= _4n;
  }
  const table = new Array(16);
  table[0] = _1n3;
  table[1] = d;
  for (let i = 2; i < 16; i++)
    table[i] = table[i - 1] * d % modulo;
  let p = table[digits[digits.length - 1]];
  for (let w = digits.length - 2; w >= 0; w--) {
    p = p * p % modulo;
    p = p * p % modulo;
    p = p * p % modulo;
    p = p * p % modulo;
    const digit = digits[w];
    if (digit !== 0)
      p = p * table[digit] % modulo;
  }
  return p;
}
function pow2(x, power, modulo) {
  if (modulo <= _1n3)
    throw new Error("pow2: expected modulus > 1, got " + modulo);
  if (power < _0n3)
    throw new Error("pow2: expected non-negative exponent, got " + power);
  let res = x;
  while (power-- > _0n3) {
    res *= res;
    res %= modulo;
  }
  return res;
}
function invert2(number, modulo) {
  if (number === _0n3)
    throw new Error("invert: expected non-zero number");
  if (modulo <= _1n3)
    throw new Error("invert: expected modulus > 1, got " + modulo);
  let a = mod(number, modulo);
  let b = modulo;
  let x = _0n3, u = _1n3;
  while (a !== _0n3) {
    const q = b / a;
    const r = b - a * q;
    const m = x - u * q;
    b = a, a = r, x = u, u = m;
  }
  const gcd = b;
  if (gcd !== _1n3)
    throw new Error("invert: does not exist");
  return mod(x, modulo);
}
function assertIsSquare(Fp, root, n) {
  const F = Fp;
  if (!F.eql(F.sqr(root), n))
    throw new Error("Cannot find square root");
}
function aoddModulus(order, fnName) {
  if ((order & _1n3) === _0n3)
    throw new Error(fnName + ": expected odd modulus, got " + order);
}
function sqrt3mod4(Fp, n) {
  const F = Fp;
  const p1div4 = (F.ORDER + _1n3) / _4n;
  const root = F.pow(n, p1div4);
  assertIsSquare(F, root, n);
  return root;
}
function sqrt5mod8(Fp, n) {
  const F = Fp;
  const p5div8 = (F.ORDER - _5n) / _8n;
  const n2 = F.mul(n, _2n2);
  const v = F.pow(n2, p5div8);
  const nv = F.mul(n, v);
  const i = F.mul(F.mul(nv, _2n2), v);
  const root = F.mul(nv, F.sub(i, F.ONE));
  assertIsSquare(F, root, n);
  return root;
}
function sqrt9mod16(P2) {
  const Fp_ = Field(P2);
  const tn = tonelliShanks(P2);
  const c1 = tn(Fp_, Fp_.neg(Fp_.ONE));
  const c2 = tn(Fp_, c1);
  const c3 = tn(Fp_, Fp_.neg(c1));
  const c4 = (P2 + _7n2) / _16n;
  return ((Fp, n) => {
    const F = Fp;
    let tv1 = F.pow(n, c4);
    let tv2 = F.mul(tv1, c1);
    const tv3 = F.mul(tv1, c2);
    const tv4 = F.mul(tv1, c3);
    const e1 = F.eql(F.sqr(tv2), n);
    const e2 = F.eql(F.sqr(tv3), n);
    tv1 = F.cmov(tv1, tv2, e1);
    tv2 = F.cmov(tv4, tv3, e2);
    const e3 = F.eql(F.sqr(tv2), n);
    const root = F.cmov(tv1, tv2, e3);
    assertIsSquare(F, root, n);
    return root;
  });
}
function tonelliShanks(P2) {
  if (P2 < _3n)
    throw new Error("sqrt is not defined for small field");
  aoddModulus(P2, "tonelliShanks");
  let Q = P2 - _1n3;
  let S = 0;
  while (Q % _2n2 === _0n3) {
    Q /= _2n2;
    S++;
  }
  let Z = _2n2;
  const _Fp = Field(P2);
  while (FpLegendre(_Fp, Z) === 1) {
    if (Z++ > 1e3)
      throw new Error("Cannot find square root: probably non-prime P");
  }
  if (S === 1)
    return sqrt3mod4;
  let cc = _Fp.pow(Z, Q);
  const Q1div2 = (Q + _1n3) / _2n2;
  return function tonelliSlow(Fp, n) {
    const F = Fp;
    if (F.is0(n))
      return n;
    if (FpLegendre(F, n) !== 1)
      throw new Error("Cannot find square root");
    let M2 = S;
    let c = F.mul(F.ONE, cc);
    let t = F.pow(n, Q);
    let R = F.pow(n, Q1div2);
    while (!F.eql(t, F.ONE)) {
      if (F.is0(t))
        throw new Error("Cannot find square root: probably non-prime P");
      let i = 1;
      let t_tmp = F.sqr(t);
      while (!F.eql(t_tmp, F.ONE)) {
        i++;
        t_tmp = F.sqr(t_tmp);
        if (i === M2)
          throw new Error("Cannot find square root");
      }
      const exponent = _1n3 << BigInt(M2 - i - 1);
      const b = F.pow(c, exponent);
      M2 = i;
      c = F.sqr(b);
      t = F.mul(t, c);
      R = F.mul(R, b);
    }
    return R;
  };
}
function FpSqrt(P2) {
  aoddModulus(P2, "Fp.sqrt");
  if (P2 % _4n === _3n)
    return sqrt3mod4;
  if (P2 % _8n === _5n)
    return sqrt5mod8;
  if (P2 % _16n === _9n)
    return sqrt9mod16(P2);
  return tonelliShanks(P2);
}
var isNegativeLE = (num, modulo) => (mod(num, modulo) & _1n3) === _1n3;
var FIELD_FIELDS = [
  "create",
  "isValid",
  "is0",
  "neg",
  "inv",
  "sqrt",
  "sqr",
  "eql",
  "add",
  "sub",
  "mul",
  "pow",
  "div",
  "addN",
  "subN",
  "mulN",
  "sqrN"
];
function validateField(field) {
  aobject2(field, "field");
  if (typeof field.ORDER !== "bigint")
    throw new TypeError('param "ORDER" is invalid: expected bigint, got ' + typeof field.ORDER);
  asafenumber(field.BYTES, "BYTES");
  asafenumber(field.BITS, "BITS");
  for (const name of FIELD_FIELDS)
    afunction(field[name], "field." + name);
  if (field.BYTES < 1 || field.BITS < 1)
    throw new Error("invalid field: expected BYTES/BITS > 0");
  if (field.ORDER <= _1n3)
    throw new Error("invalid field: expected ORDER > 1, got " + field.ORDER);
  return field;
}
function FpInvertBatch(Fp, nums, passZero = false) {
  validateField(Fp);
  aarray(nums, "nums");
  abool2(passZero, "passZero");
  const F = Fp;
  const inverted = new Array(nums.length).fill(passZero ? F.ZERO : void 0);
  const multipliedAcc = nums.reduce((acc, num, i) => {
    if (F.is0(num))
      return acc;
    inverted[i] = acc;
    return F.mul(acc, num);
  }, F.ONE);
  const invertedAcc = F.inv(multipliedAcc);
  nums.reduceRight((acc, num, i) => {
    if (F.is0(num))
      return acc;
    inverted[i] = F.mul(acc, inverted[i]);
    return F.mul(acc, num);
  }, invertedAcc);
  return inverted;
}
function FpLegendre(Fp, n) {
  validateField(Fp);
  const F = Fp;
  aoddModulus(F.ORDER, "FpLegendre");
  const p1mod2 = (F.ORDER - _1n3) / _2n2;
  const powered = F.pow(n, p1mod2);
  const yes = F.eql(powered, F.ONE);
  const zero = F.eql(powered, F.ZERO);
  const no = F.eql(powered, F.neg(F.ONE));
  if (!yes && !zero && !no)
    throw new Error("invalid Legendre symbol result");
  return yes ? 1 : zero ? 0 : -1;
}
function nLength(n, nBitLength) {
  if (nBitLength !== void 0)
    anumber2(nBitLength);
  if (n <= _0n3)
    throw new Error("invalid n length: expected positive n, got " + n);
  if (nBitLength !== void 0 && nBitLength < 1)
    throw new Error("invalid n length: expected positive bit length, got " + nBitLength);
  const bits = bitLen(n);
  if (nBitLength !== void 0 && nBitLength < bits)
    throw new Error(`invalid n length: expected nBitLength (${nBitLength}) >= bitLen(n) (${bits})`);
  const _nBitLength = nBitLength !== void 0 ? nBitLength : bits;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}
var FIELD_SQRT = /* @__PURE__ */ new WeakMap();
var _Field = class {
  ORDER;
  BITS;
  BYTES;
  isLE;
  ZERO = _0n3;
  ONE = _1n3;
  _lengths;
  _mod;
  constructor(ORDER, opts = {}) {
    if (ORDER <= _1n3)
      throw new Error("invalid field: expected ORDER > 1, got " + ORDER);
    let _nbitLength = void 0;
    this.isLE = false;
    if (opts != null && typeof opts === "object") {
      if (typeof opts.BITS === "number")
        _nbitLength = opts.BITS;
      if (typeof opts.sqrt === "function")
        Object.defineProperty(this, "sqrt", { value: opts.sqrt, enumerable: true });
      if (typeof opts.isLE === "boolean")
        this.isLE = opts.isLE;
      if (opts.allowedLengths)
        this._lengths = Object.freeze(opts.allowedLengths.slice());
      if (typeof opts.modFromBytes === "boolean")
        this._mod = opts.modFromBytes;
    }
    const { nBitLength, nByteLength } = nLength(ORDER, _nbitLength);
    if (nByteLength > 2048)
      throw new Error("invalid field: expected ORDER of <= 2048 bytes");
    this.ORDER = ORDER;
    this.BITS = nBitLength;
    this.BYTES = nByteLength;
    Object.freeze(this);
  }
  create(num) {
    return mod(num, this.ORDER);
  }
  isValid(num) {
    if (typeof num !== "bigint")
      throw new TypeError("invalid field element: expected bigint, got " + typeof num);
    return _0n3 <= num && num < this.ORDER;
  }
  is0(num) {
    return num === _0n3;
  }
  // is valid and invertible
  isValidNot0(num) {
    return !this.is0(num) && this.isValid(num);
  }
  isOdd(num) {
    return (num & _1n3) === _1n3;
  }
  neg(num) {
    return mod(-num, this.ORDER);
  }
  eql(lhs, rhs) {
    return lhs === rhs;
  }
  sqr(num) {
    return mod(num * num, this.ORDER);
  }
  add(lhs, rhs) {
    return mod(lhs + rhs, this.ORDER);
  }
  sub(lhs, rhs) {
    return mod(lhs - rhs, this.ORDER);
  }
  mul(lhs, rhs) {
    return mod(lhs * rhs, this.ORDER);
  }
  pow(num, power) {
    return pow(num, power, this.ORDER);
  }
  div(lhs, rhs) {
    return mod(lhs * invert2(rhs, this.ORDER), this.ORDER);
  }
  // Same as above, but doesn't normalize
  sqrN(num) {
    return num * num;
  }
  addN(lhs, rhs) {
    return lhs + rhs;
  }
  subN(lhs, rhs) {
    return lhs - rhs;
  }
  mulN(lhs, rhs) {
    return lhs * rhs;
  }
  inv(num) {
    return invert2(num, this.ORDER);
  }
  sqrt(num) {
    let sqrt = FIELD_SQRT.get(this);
    if (!sqrt)
      FIELD_SQRT.set(this, sqrt = FpSqrt(this.ORDER));
    return sqrt(this, num);
  }
  toBytes(num) {
    return this.isLE ? numberToBytesLE(num, this.BYTES) : numberToBytesBE(num, this.BYTES);
  }
  fromBytes(bytes, skipValidation = false) {
    abytes3(bytes);
    const { _lengths: allowedLengths, BYTES, isLE: isLE2, ORDER, _mod: modFromBytes } = this;
    if (allowedLengths) {
      if (bytes.length < 1 || !allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
        throw new Error("Field.fromBytes: expected " + allowedLengths + " bytes, got " + bytes.length);
      }
      const padded = new Uint8Array(BYTES);
      padded.set(bytes, isLE2 ? 0 : padded.length - bytes.length);
      bytes = padded;
    }
    if (bytes.length !== BYTES)
      throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
    let scalar = isLE2 ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    if (modFromBytes)
      scalar = mod(scalar, ORDER);
    if (!skipValidation) {
      if (!this.isValid(scalar))
        throw new Error("invalid field element: outside of range 0..ORDER");
    }
    return scalar;
  }
  // TODO: we don't need it here, move out to separate fn
  invertBatch(lst) {
    return FpInvertBatch(this, lst, true);
  }
  // We can't move this out because Fp6, Fp12 implement it
  // and it's unclear what to return in there.
  cmov(a, b, condition) {
    abool2(condition, "condition");
    return condition ? b : a;
  }
};
function Field(ORDER, opts = {}) {
  Object.freeze(_Field.prototype);
  return new _Field(ORDER, opts);
}

// node_modules/@noble/curves/abstract/curve.js
var _0n4 = /* @__PURE__ */ BigInt(0);
var _1n4 = /* @__PURE__ */ BigInt(1);
var _4n2 = /* @__PURE__ */ BigInt(4);
var BLIND_BYTES = 16;
var BLIND_BITS = 128;
var FW_WINDOW = 5;
var TABLE_BYTES_MAX = /* @__PURE__ */ (() => 2 ** 31)();
function validatePointCons(Point2) {
  const pc = Point2;
  if (typeof pc !== "function")
    throw new TypeError('"Point" expected constructor, got type=' + typeof Point2);
  afunction(pc.fromAffine, "Point.fromAffine");
  afunction(pc.fromBytes, "Point.fromBytes");
  afunction(pc.fromHex, "Point.fromHex");
  aobject2(pc.BASE, "Point.BASE");
  aobject2(pc.ZERO, "Point.ZERO");
  validateField(pc.Fp);
  validateField(pc.Fn);
}
function normalizeZ(c, points) {
  validatePointCons(c);
  validateMSMPoints(points, c);
  const invertedZs = FpInvertBatch(c.Fp, points.map((p) => p.Z));
  return points.map((p, i) => c.fromAffine(p.toAffine(invertedZs[i])));
}
function validateW(W2, bits, min = 1) {
  if (!Number.isSafeInteger(W2) || W2 < min || W2 > bits)
    throw new Error("invalid window size, expected [" + min + ".." + bits + "], got W=" + W2);
}
function validateTableBytes(numPoints, fpBytes) {
  const bytes = numPoints * (4 * fpBytes + 128);
  if (bytes > TABLE_BYTES_MAX)
    throw new Error("invalid window size: table would need ~" + Math.ceil(bytes / 2 ** 20) + " MiB, max " + TABLE_BYTES_MAX / 2 ** 20 + " MiB");
}
function probeRandomBytes(randomBytes4, length) {
  if (randomBytes4 === void 0)
    return void 0;
  afunction(randomBytes4, "randomBytes");
  try {
    const probe = randomBytes4(length);
    if (!isBytes3(probe) || probe.length !== length)
      return void 0;
  } catch {
    return void 0;
  }
  return randomBytes4;
}
function validateMSMPoints(points, c) {
  aarray(points, "points");
  points.forEach((p, i) => {
    if (!(p instanceof c))
      throw new Error("invalid point at index " + i);
  });
}
function validateMSMScalars(scalars, field, maxScalar) {
  if (!Array.isArray(scalars))
    throw new Error("array of scalars expected");
  scalars.forEach((s, i) => {
    const ok = maxScalar === void 0 ? field.isValid(s) : isPosBig(s) && s < maxScalar;
    if (!ok)
      throw new Error("invalid scalar at index " + i);
  });
}
var pointWindowSizes = /* @__PURE__ */ new WeakMap();
function getWindowSize(P2) {
  return pointWindowSizes.get(P2) || 1;
}
function oddMultiples(p, size) {
  const dbl = p.double();
  const t = [p];
  for (let j = 1; j < size; j++)
    t.push(t[j - 1].add(dbl));
  return t;
}
function wnafDigits(n, W2) {
  const size = 2 ** W2;
  const half = size / 2;
  const mask = BigInt(size - 1);
  const d = [];
  while (n > _0n4) {
    let w = 0;
    if (n & _1n4) {
      w = Number(n & mask);
      if (w >= half)
        w -= size;
      n -= BigInt(w);
    }
    d.push(w);
    n >>= _1n4;
  }
  return d;
}
function signedWindowDigits(n, W2, windows) {
  const size = 2 ** W2;
  const half = size / 2;
  const mask = BigInt(size - 1);
  const shiftBy = BigInt(W2);
  const d = [];
  for (let w = 0; w < windows; w++) {
    let v = Number(n & mask);
    n >>= shiftBy;
    if (v > half) {
      v -= size;
      n += _1n4;
    }
    d.push(v);
  }
  if (n !== _0n4)
    throw new Error("invalid wnaf");
  return d;
}
function wnafWalk(zero, tables, digits) {
  let max = 0;
  for (const d of digits)
    max = Math.max(max, d.length);
  let acc = zero;
  for (let bit = max - 1; bit >= 0; bit--) {
    if (bit !== max - 1)
      acc = acc.double();
    for (let i = 0; i < digits.length; i++) {
      const w = digits[i][bit];
      if (w) {
        const item = tables[i][Math.abs(w) - 1 >> 1];
        acc = acc.add(w < 0 ? item.negate() : item);
      }
    }
  }
  return acc;
}
var ScalarMultiplier = class {
  Point;
  BASE;
  ZERO;
  randomBytes;
  wnafPrecomputes = /* @__PURE__ */ new WeakMap();
  baseCanBeBlinded;
  bits;
  // Parametrized with a given Point class (not individual point)
  constructor(Point2, randomBytes4) {
    validatePointCons(Point2);
    this.randomBytes = probeRandomBytes(randomBytes4, BLIND_BYTES);
    this.Point = Point2;
    this.BASE = Point2.BASE;
    this.ZERO = Point2.ZERO;
    this.bits = Point2.Fn.BITS;
  }
  /**
   * Creates a signed fixed-window wNAF precomputation table: for every window w, the
   * multiples `[1..2^(W−1)]⋅2^(w⋅W)⋅P`, flattened. All doublings are baked into the table,
   * so cached multiplication is additions-only. `windows = ceil(bits/W) + 1`: the extra
   * window absorbs the final carry of signed-digit recoding.
   * For a 256-bit curve and W=6, the table is 44⋅32 = 1408 points.
   * @param point - Point instance
   * @param W - window size
   * @param bits - scalar bitlength the table must cover
   */
  buildWnafTable(point, W2, bits) {
    const windows = Math.ceil(bits / W2) + 1;
    const half = 2 ** (W2 - 1);
    const comp = [];
    let base = point;
    for (let w = 0; w < windows; w++) {
      let acc = base;
      for (let i = 0; i < half; i++) {
        comp.push(acc);
        acc = acc.add(base);
      }
      base = comp[comp.length - 1].double();
    }
    return { W: W2, bits, windows, comp };
  }
  /**
   * Implements ec multiplication using precomputed signed fixed-window wNAF tables.
   * Constant-time: fixed window count with one table addition per window — zero digits feed
   * the fake accumulator — and no doublings; the lookup scans the whole window slice.
   * Scalar bounds are validated by the public entry points ({@link ScalarMultiplier.mulCT},
   * {@link ScalarMultiplier.mulCTBlinded}, {@link ScalarMultiplier.mulUnsafe});
   * signedWindowDigits throws if `n` exceeds the table.
   * @returns real and fake (for const-time) points
   */
  wnafCachedCT(precomputes, n) {
    const { W: W2, windows, comp } = precomputes;
    const half = 2 ** (W2 - 1);
    const digits = signedWindowDigits(n, W2, windows);
    let p = this.ZERO;
    let f = this.BASE;
    for (let w = 0; w < windows; w++) {
      const digit = digits[w];
      const start = w * half;
      const idx = Math.abs(digit) - 1;
      let sel = comp[start];
      for (let i = 1; i < half; i++)
        sel = i === idx ? comp[start + i] : sel;
      const neg = sel.negate();
      if (digit === 0)
        f = f.add(comp[start]);
      else
        p = p.add(digit < 0 ? neg : sel);
    }
    return { p, f };
  }
  // Cache key is point identity plus (W, bits); at most two entries exist per point (public-width
  // `Fn.BITS` and blinded `Fn.BITS + BLIND_BITS`). Callers must not reuse the same point with
  // incompatible `transform(...)` layouts and expect a separate cache entry.
  getWnafPrecomputes(W2, point, bits, transform) {
    let entries = this.wnafPrecomputes.get(point);
    let comp = entries?.find((entry) => entry.W === W2 && entry.bits === bits);
    if (!comp) {
      comp = this.buildWnafTable(point, W2, bits);
      if (typeof transform === "function")
        comp = { ...comp, comp: transform(comp.comp) };
      if (!entries) {
        entries = [];
        this.wnafPrecomputes.set(point, entries);
      }
      entries.push(comp);
    }
    return comp;
  }
  assertPoint(point) {
    if (!(point instanceof this.Point))
      throw new TypeError('"point" expected Point instance, got type=' + typeof point);
  }
  // Shared prologue of the constant-time entry points. Rejects scalar 0: in key/signature-style
  // callers a zero scalar means broken upstream plumbing, and concrete Points already reject it.
  // Uses inRange instead of Fn.isValidNot0: validateField() only certifies the arithmetic subset.
  validateMulInput(point, scalar) {
    this.assertPoint(point);
    if (!inRange(scalar, _1n4, this.Point.Fn.ORDER))
      throw new Error("invalid scalar");
  }
  // Constant-time dispatch shared by mulCT / mulCTBlinded. Un-precomputed points (W===1, e.g.
  // ECDH peer keys) skip building a throwaway cached table in favor of a small fixed-window
  // multiply. `n` must be < 2^bits.
  runCT(point, n, bits, transform) {
    const W2 = getWindowSize(point);
    if (W2 === 1)
      return this.fixedWindowCT(point, n, bits);
    return this.wnafCachedCT(this.getWnafPrecomputes(W2, point, bits, transform), n);
  }
  mulCT(point, scalar, transform) {
    this.validateMulInput(point, scalar);
    return this.runCT(point, scalar, this.bits, transform);
  }
  mulCTBlinded(point, scalar, transform) {
    this.validateMulInput(point, scalar);
    if (this.randomBytes === void 0)
      throw new Error("randomBytes is required for scalar blinding");
    const bits = this.Point.Fn.BITS + BLIND_BITS;
    const blind = this.randomBytes(BLIND_BYTES);
    if (!isBytes3(blind) || blind.length !== BLIND_BYTES)
      throw new Error("randomBytes returned invalid byte array");
    blind[0] = blind[0] & 63 | 128;
    const n = scalar + bytesToNumberBE(blind) * this.Point.Fn.ORDER;
    return this.runCT(point, n, bits, transform);
  }
  /**
   * Constant-time multiplication `n*point` for an un-precomputed point, via a small fixed window.
   * A cached wNAF table only pays off when reused; a flat 2^FW_WINDOW table (`size-1` adds) is
   * far cheaper to build for a single use. The point-operation sequence is independent of `n`:
   * build the table, then per window exactly FW_WINDOW doublings, a data-oblivious scan over
   * every table entry, and one addition (adds the identity when the window digit is 0 — never
   * skipped).
   *
   * `n` must be `< 2^bits`. Assumes complete addition (adding the identity costs the same as any
   * add), which holds for the Weierstrass/Edwards point types used here. The table is left in
   * projective form (no normalizeZ): normalizing this small a table costs more than the
   * mixed-add savings it would buy for a single multiply.
   * @returns real point `p`; `f` duplicates it only to match {@link wnafCachedCT}'s return shape
   * (this path needs no fake accumulator — its op-count is already scalar-independent).
   */
  fixedWindowCT(point, n, bits) {
    const W2 = FW_WINDOW;
    const size = 1 << W2;
    const mask = bitMask(W2);
    const table = new Array(size);
    table[0] = this.ZERO;
    for (let i = 1; i < size; i++)
      table[i] = table[i - 1].add(point);
    const windows = Math.ceil(bits / W2);
    let acc = this.ZERO;
    for (let window = windows - 1; window >= 0; window--) {
      if (window !== windows - 1)
        for (let d = 0; d < W2; d++)
          acc = acc.double();
      const digit = Number(n >> BigInt(window * W2) & mask);
      let sel = table[0];
      for (let i = 1; i < size; i++)
        sel = i === digit ? table[i] : sel;
      acc = acc.add(sel);
    }
    return { p: acc, f: acc };
  }
  shouldBlind(point, cofactor) {
    if (this.randomBytes === void 0)
      return false;
    if (cofactor === _1n4)
      return true;
    if (point !== this.BASE)
      return false;
    if (this.baseCanBeBlinded === void 0)
      this.baseCanBeBlinded = this.mulUnsafe(this.BASE, this.Point.Fn.ORDER).is0();
    return this.baseCanBeBlinded;
  }
  mulSecret(point, scalar, cofactor, transform) {
    return this.shouldBlind(point, cofactor) ? this.mulCTBlinded(point, scalar, transform) : this.mulCT(point, scalar, transform);
  }
  mulUnsafe(point, scalar, transform) {
    this.assertPoint(point);
    if (!isPosBig(scalar))
      throw new Error("invalid scalar");
    const W2 = getWindowSize(point);
    if (W2 === 1 || scalar >= this.Point.Fn.ORDER)
      return mulAddUnsafe(this.Point, [point], [scalar], true);
    const precomputes = this.getWnafPrecomputes(W2, point, this.bits, transform);
    return this.wnafCachedCT(precomputes, scalar).p;
  }
  // Remembers the window size used for precomputed wNAF multiplication of the given point
  // and drops any previously built tables. Usually only the base point is precomputed.
  // W=1 resets the point to the un-precomputed (table-less) paths.
  // W is additionally capped so tables stay under ~2 GiB ({@link TABLE_BYTES_MAX}).
  setWindowSize(point, W2) {
    this.assertPoint(point);
    validateW(W2, this.bits);
    const windows = Math.ceil((this.bits + BLIND_BITS) / W2) + 1;
    validateTableBytes(windows * 2 ** (W2 - 1), this.Point.Fp.BYTES);
    pointWindowSizes.set(point, W2);
    this.wnafPrecomputes.delete(point);
  }
  // True when a window size is set: tables themselves are built lazily on first multiply.
  hasWindowSize(point) {
    return getWindowSize(point) !== 1;
  }
};
function mulAddUnsafe(c, points, scalars, allowOversized = false) {
  validatePointCons(c);
  validateMSMPoints(points, c);
  abool2(allowOversized, "allowOversized");
  validateMSMScalars(scalars, c.Fn, allowOversized ? c.Fn.ORDER ** _4n2 : void 0);
  if (points.length !== scalars.length)
    throw new Error("arrays of points and scalars must have equal length");
  const tables = points.map((p) => oddMultiples(p, 4));
  const digits = scalars.map((n) => wnafDigits(n, 4));
  return wnafWalk(c.ZERO, tables, digits);
}
function createField(order, field, isLE2) {
  if (field) {
    if (field.ORDER !== order)
      throw new Error("Field.ORDER must match order: Fp == p, Fn == n");
    validateField(field);
    return field;
  } else {
    return Field(order, { isLE: isLE2 });
  }
}
function createCurveFields(type, CURVE, curveOpts = {}, FpFnLE) {
  if (type !== "weierstrass" && type !== "edwards")
    throw new Error('expected curve type "weierstrass" or "edwards"');
  if (FpFnLE === void 0)
    FpFnLE = type === "edwards";
  if (!CURVE || typeof CURVE !== "object")
    throw new Error(`expected valid ${type} CURVE object`);
  validateObject(curveOpts);
  for (const p of ["p", "n", "h"]) {
    const val = CURVE[p];
    if (!(isPosBig(val) && val !== _0n4))
      throw new Error(`CURVE.${p} must be positive bigint`);
  }
  const Fp = createField(CURVE.p, curveOpts.Fp, FpFnLE);
  const Fn = createField(CURVE.n, curveOpts.Fn, FpFnLE);
  const _b2 = type === "weierstrass" ? "b" : "d";
  const params = ["Gx", "Gy", "a", _b2];
  for (const p of params) {
    if (!Fp.isValid(CURVE[p]))
      throw new Error(`CURVE.${p} must be valid field element of CURVE.Fp`);
  }
  CURVE = Object.freeze(Object.assign({}, CURVE));
  return { CURVE, Fp, Fn };
}
function createKeygen(randomSecretKey, getPublicKey2) {
  return function keygen(seed) {
    const secretKey = randomSecretKey(seed);
    return { secretKey, publicKey: getPublicKey2(secretKey) };
  };
}

// node_modules/@noble/curves/abstract/edwards.js
var _0n5 = /* @__PURE__ */ BigInt(0);
var _1n5 = /* @__PURE__ */ BigInt(1);
var _2n3 = /* @__PURE__ */ BigInt(2);
var _4n3 = /* @__PURE__ */ BigInt(4);
var _8n2 = /* @__PURE__ */ BigInt(8);
function isEdValidXY(Fp, CURVE, x, y) {
  const x2 = Fp.sqr(x);
  const y2 = Fp.sqr(y);
  const left = Fp.add(Fp.mul(CURVE.a, x2), y2);
  const right = Fp.add(Fp.ONE, Fp.mul(CURVE.d, Fp.mul(x2, y2)));
  return Fp.eql(left, right);
}
function edwards(params, extraOpts = {}) {
  validateObject(extraOpts, {}, {}, "extraOpts");
  const opts = extraOpts;
  const validated = createCurveFields("edwards", params, opts, opts.FpFnLE);
  const { Fp, Fn } = validated;
  let CURVE = validated.CURVE;
  const { h: cofactor } = CURVE;
  if (FpLegendre(Fp, CURVE.a) !== 1)
    throw new Error("edwards: CURVE.a must be a square in Fp for complete addition formulas");
  if (FpLegendre(Fp, CURVE.d) !== -1)
    throw new Error("edwards: CURVE.d must be a non-square in Fp for complete addition formulas");
  validateObject(opts, {}, { uvRatio: "function", randomBytes: "function" });
  const randomBytes4 = opts.randomBytes === void 0 ? randomBytes3 : opts.randomBytes;
  const MASK = _2n3 << BigInt(Fp.BYTES * 8) - _1n5;
  function isOdd(n) {
    if (!Fp.isOdd)
      throw new Error("Field does not have .isOdd()");
    return Fp.isOdd(n);
  }
  const uvRatio2 = opts.uvRatio === void 0 ? (u, v) => {
    try {
      return { isValid: true, value: Fp.sqrt(Fp.div(u, v)) };
    } catch (e) {
      return { isValid: false, value: _0n5 };
    }
  } : opts.uvRatio;
  if (!isEdValidXY(Fp, CURVE, CURVE.Gx, CURVE.Gy))
    throw new Error("bad curve params: generator point");
  const mulA = Fp.eql(CURVE.a, Fp.neg(Fp.ONE)) ? (x) => Fp.neg(x) : Fp.eql(CURVE.a, Fp.ONE) ? (x) => x : (x) => Fp.mul(CURVE.a, x);
  function acoord(title, n, banZero = false) {
    const min = banZero ? _1n5 : _0n5;
    aInRange("coordinate " + title, n, min, MASK);
    return n;
  }
  function aedpoint(other) {
    if (!(other instanceof Point2))
      throw new Error("EdwardsPoint expected");
  }
  class Point2 {
    static BASE = new Point2(CURVE.Gx, CURVE.Gy, Fp.ONE, Fp.mul(CURVE.Gx, CURVE.Gy));
    static ZERO = new Point2(Fp.ZERO, Fp.ONE, Fp.ONE, Fp.ZERO);
    static Fp = Fp;
    static Fn = Fn;
    X;
    Y;
    Z;
    T;
    constructor(X, Y, Z, T) {
      this.X = acoord("x", X);
      this.Y = acoord("y", Y);
      this.Z = acoord("z", Z, true);
      this.T = acoord("t", T);
      Object.freeze(this);
    }
    static CURVE() {
      return CURVE;
    }
    /**
     * Create one extended Edwards point from affine coordinates.
     * Does NOT validate that the point is on-curve or torsion-free.
     * Use `.assertValidity()` on adversarial inputs.
     */
    static fromAffine(p) {
      if (p instanceof Point2)
        throw new Error("extended point not allowed");
      const { x, y } = p || {};
      acoord("x", x);
      acoord("y", y);
      return new Point2(x, y, Fp.ONE, Fp.mul(x, y));
    }
    // Uses algo from RFC8032 5.1.3.
    static fromBytes(bytes, zip215 = false) {
      const len = Fp.BYTES;
      const { a, d } = CURVE;
      bytes = copyBytes(abytes3(bytes, len, "point"));
      abool2(zip215, "zip215");
      const normed = copyBytes(bytes);
      const lastByte = bytes[len - 1];
      normed[len - 1] = lastByte & ~128;
      const y = bytesToNumberLE(normed);
      const max = zip215 ? MASK : Fp.ORDER;
      aInRange("point.y", y, _0n5, max);
      const y2 = Fp.sqr(y);
      const u = Fp.sub(y2, Fp.ONE);
      const v = Fp.sub(Fp.mulN(d, y2), a);
      let { isValid, value: x } = uvRatio2(u, v);
      if (!isValid)
        throw new Error("bad point: invalid y coordinate");
      const isXOdd = isOdd(x);
      const isLastByteOdd = (lastByte & 128) !== 0;
      if (!zip215 && Fp.is0(x) && isLastByteOdd)
        throw new Error("bad point: x=0 and x_0=1");
      if (isLastByteOdd !== isXOdd)
        x = Fp.neg(x);
      return Point2.fromAffine({ x, y });
    }
    static fromHex(hex, zip215 = false) {
      return Point2.fromBytes(hexToBytes3(hex), zip215);
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    precompute(windowSize = 6, isLazy = true) {
      wnaf.setWindowSize(this, windowSize);
      if (!isLazy)
        this.multiply(_2n3);
      return this;
    }
    // Useful in fromAffine() - not for fromBytes(), which always created valid points.
    assertValidity() {
      const p = this;
      const { a, d } = CURVE;
      if (p.is0())
        throw new Error("bad point: ZERO");
      const { X, Y, Z, T } = p;
      const X2 = Fp.sqr(X);
      const Y2 = Fp.sqr(Y);
      const Z2 = Fp.sqr(Z);
      const Z4 = Fp.sqr(Z2);
      const aX2 = Fp.mul(X2, a);
      const left = Fp.mul(Fp.add(aX2, Y2), Z2);
      const right = Fp.add(Z4, Fp.mul(d, Fp.mul(X2, Y2)));
      if (!Fp.eql(left, right))
        throw new Error("bad point: equation left != right (1)");
      const XY = Fp.mul(X, Y);
      const ZT = Fp.mul(Z, T);
      if (!Fp.eql(XY, ZT))
        throw new Error("bad point: equation left != right (2)");
    }
    // Compare one point to another.
    equals(other) {
      aedpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      const X1Z2 = Fp.mul(X1, Z2);
      const X2Z1 = Fp.mul(X2, Z1);
      const Y1Z2 = Fp.mul(Y1, Z2);
      const Y2Z1 = Fp.mul(Y2, Z1);
      return Fp.eql(X1Z2, X2Z1) && Fp.eql(Y1Z2, Y2Z1);
    }
    is0() {
      return this.equals(Point2.ZERO);
    }
    negate() {
      return new Point2(Fp.neg(this.X), this.Y, this.Z, Fp.neg(this.T));
    }
    // Fast algo for doubling Extended Point.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
    // Cost: 4M + 4S + 1*a + 6add + 1*2.
    double() {
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const A = Fp.sqr(X1);
      const B2 = Fp.sqr(Y1);
      const C2 = Fp.mul(Fp.sqr(Z1), _2n3);
      const D = mulA(A);
      const x1y1 = Fp.addN(X1, Y1);
      const E = Fp.sub(Fp.subN(Fp.sqr(x1y1), A), B2);
      const G2 = Fp.addN(D, B2);
      const F = Fp.subN(G2, C2);
      const H = Fp.subN(D, B2);
      const X3 = Fp.mul(E, F);
      const Y3 = Fp.mul(G2, H);
      const T3 = Fp.mul(E, H);
      const Z3 = Fp.mul(F, G2);
      return new Point2(X3, Y3, Z3, T3);
    }
    // Fast algo for adding 2 Extended Points.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
    // Cost: 9M + 1*a + 1*d + 7add.
    add(other) {
      aedpoint(other);
      const { d } = CURVE;
      const { X: X1, Y: Y1, Z: Z1, T: T1 } = this;
      const { X: X2, Y: Y2, Z: Z2, T: T2 } = other;
      const A = Fp.mul(X1, X2);
      const B2 = Fp.mul(Y1, Y2);
      const C2 = Fp.mul(Fp.mulN(T1, d), T2);
      const D = Fp.mul(Z1, Z2);
      const E = Fp.sub(Fp.subN(Fp.mulN(Fp.addN(X1, Y1), Fp.addN(X2, Y2)), A), B2);
      const F = Fp.subN(D, C2);
      const G2 = Fp.addN(D, C2);
      const H = Fp.sub(B2, mulA(A));
      const X3 = Fp.mul(E, F);
      const Y3 = Fp.mul(G2, H);
      const T3 = Fp.mul(E, H);
      const Z3 = Fp.mul(F, G2);
      return new Point2(X3, Y3, Z3, T3);
    }
    subtract(other) {
      aedpoint(other);
      return this.add(other.negate());
    }
    // Constant-time multiplication.
    multiply(scalar) {
      if (!Fn.isValidNot0(scalar))
        throw new RangeError("invalid scalar: expected 1 <= sc < curve.n");
      const { p, f } = wnaf.mulSecret(this, scalar, cofactor, normalize);
      return normalize([p, f])[0];
    }
    // Non-constant-time multiplication. Uses double-and-add algorithm.
    // It's faster, but should only be used when you don't care about
    // an exposed private key e.g. sig verification.
    // Keeps the same subgroup-scalar contract: 0 is allowed for public-scalar callers, but
    // n and larger values are rejected instead of being reduced mod n to the identity point.
    multiplyUnsafe(scalar) {
      if (!Fn.isValid(scalar))
        throw new RangeError("invalid scalar: expected 0 <= sc < curve.n");
      if (scalar === _0n5)
        return Point2.ZERO;
      if (this.is0() || scalar === _1n5)
        return this;
      return wnaf.mulUnsafe(this, scalar, normalize);
    }
    // Checks if point is of small order.
    // If you add something to small order point, you will have "dirty"
    // point with torsion component.
    // Clears cofactor and checks if the result is 0.
    isSmallOrder() {
      return this.clearCofactor().is0();
    }
    // Multiplies point by curve order and checks if the result is 0.
    // Returns `false` is the point is dirty.
    isTorsionFree() {
      return wnaf.mulUnsafe(this, CURVE.n).is0();
    }
    // Converts Extended point to default (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    toAffine(invertedZ) {
      const p = this;
      let iz = invertedZ;
      if (iz != null && typeof iz !== "bigint")
        throw new TypeError('"invertedZ" expected bigint, got type=' + typeof iz);
      const { X, Y, Z } = p;
      const is0 = p.is0();
      if (iz == null)
        iz = is0 ? Fp.create(_8n2) : Fp.inv(Z);
      const x = Fp.mul(X, iz);
      const y = Fp.mul(Y, iz);
      const zz = Fp.mul(Z, iz);
      if (is0)
        return { x: Fp.ZERO, y: Fp.ONE };
      if (!Fp.eql(zz, Fp.ONE))
        throw new Error("invZ was invalid");
      return { x, y };
    }
    clearCofactor() {
      if (cofactor === _1n5)
        return this;
      if (cofactor === _2n3)
        return this.double();
      if (cofactor === _4n3)
        return this.double().double();
      if (cofactor === _8n2)
        return this.double().double().double();
      return this.multiplyUnsafe(cofactor);
    }
    toBytes() {
      const { x, y } = this.toAffine();
      const bytes = Fp.toBytes(y);
      bytes[bytes.length - 1] |= isOdd(x) ? 128 : 0;
      return bytes;
    }
    toHex() {
      return bytesToHex3(this.toBytes());
    }
    toString() {
      return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
    }
  }
  const normalize = (points) => normalizeZ(Point2, points);
  const wnaf = new ScalarMultiplier(Point2, randomBytes4);
  if (wnaf.bits >= 6)
    Point2.BASE.precompute(6);
  Object.freeze(Point2.prototype);
  Object.freeze(Point2);
  return Point2;
}

// node_modules/@noble/curves/abstract/montgomery.js
var _0n6 = /* @__PURE__ */ BigInt(0);
var _1n6 = /* @__PURE__ */ BigInt(1);
var _2n4 = /* @__PURE__ */ BigInt(2);
function cmask(P2, swap) {
  return P2 + swap - (swap >> _1n6 << _1n6);
}
function cswap(P2) {
  const offset = BigInt(6) * P2;
  return (mask, x_2, x_3) => {
    const sum = x_2 + x_3;
    const d = offset + x_3 - x_2;
    const a = (d * mask + x_2) % P2;
    return { x_2: a, x_3: sum - a };
  };
}
function validateOpts(curve) {
  validateObject(curve, {
    P: "bigint",
    type: "string",
    adjustScalarBytes: "function",
    powPminus2: "function"
  }, {
    randomBytes: "function",
    scalarMultBase: "function"
  });
  return Object.freeze({ ...curve });
}
function montgomery(curveDef) {
  const CURVE = validateOpts(curveDef);
  const { P: P2, type, adjustScalarBytes: adjustScalarBytes2, powPminus2, randomBytes: rand } = CURVE;
  const mulBaseHook = CURVE.scalarMultBase;
  const is25519 = type === "x25519";
  if (!is25519 && type !== "x448")
    throw new Error("invalid type");
  const randomBytes_ = rand === void 0 ? randomBytes3 : rand;
  const montgomeryBits = is25519 ? 255 : 448;
  const swap = cswap(P2);
  const fieldLen = is25519 ? 32 : 56;
  const Gu = is25519 ? BigInt(9) : BigInt(5);
  const a24 = is25519 ? BigInt(121665) : BigInt(39081);
  const minScalar = is25519 ? _2n4 ** BigInt(254) : _2n4 ** BigInt(447);
  const maxAdded = is25519 ? BigInt(8) * (_2n4 ** BigInt(251) - _1n6) : BigInt(4) * (_2n4 ** BigInt(445) - _1n6);
  const maxScalar = minScalar + maxAdded + _1n6;
  const modP = (n) => mod(n, P2);
  const GuBytes = encodeU(Gu);
  function encodeU(u) {
    return numberToBytesLE(modP(u), fieldLen);
  }
  function decodeU(u) {
    const _u = copyBytes(abytes3(u, fieldLen, "uCoordinate"));
    if (is25519)
      _u[31] &= 127;
    return modP(bytesToNumberLE(_u));
  }
  function decodeScalar(scalar) {
    return bytesToNumberLE(adjustScalarBytes2(copyBytes(abytes3(scalar, fieldLen, "scalar"))));
  }
  const lowOrderU = new Set(is25519 ? [
    _0n6,
    _1n6,
    P2 - _1n6,
    BigInt("325606250916557431795983626356110631294008115727848805560023387167927233504"),
    BigInt("39382357235489614581723060781553021112529911719440698176882885853963445705823")
  ] : [_0n6, _1n6, P2 - _1n6]);
  function scalarMult(scalar, u) {
    const pointU = decodeU(u);
    if (lowOrderU.has(pointU))
      throw new Error("invalid private or public key received");
    const pu = montgomeryLadder(pointU, decodeScalar(scalar));
    if (pu === _0n6)
      throw new Error("invalid private or public key received");
    return encodeU(pu);
  }
  function scalarMultBase(scalar) {
    if (mulBaseHook === void 0)
      return scalarMult(scalar, GuBytes);
    const k = decodeScalar(scalar);
    aInRange("scalar", k, minScalar, maxScalar);
    const pu = modP(mulBaseHook(k));
    if (pu === _0n6)
      throw new Error("invalid private or public key received");
    return encodeU(pu);
  }
  const getPublicKey2 = scalarMultBase;
  const getSharedSecret2 = scalarMult;
  function montgomeryLadder(u, scalar) {
    aInRange("u", u, _0n6, P2);
    aInRange("scalar", scalar, minScalar, maxScalar);
    const k = scalar;
    const x_1 = u;
    let x_2 = _1n6;
    let z_2 = _0n6;
    let x_3 = u;
    let z_3 = _1n6;
    const kx = k ^ k >> _1n6;
    for (let t = BigInt(montgomeryBits - 1); t >= _0n6; t--) {
      const mask2 = cmask(P2, kx >> t);
      ({ x_2, x_3 } = swap(mask2, x_2, x_3));
      ({ x_2: z_2, x_3: z_3 } = swap(mask2, z_2, z_3));
      const A = x_2 + z_2;
      const AA = modP(A * A);
      const B2 = x_2 - z_2;
      const BB = modP(B2 * B2);
      const E = AA - BB;
      const C2 = x_3 + z_3;
      const D = x_3 - z_3;
      const DA = modP(D * A);
      const CB = modP(C2 * B2);
      const dacb = DA + CB;
      const da_cb = DA - CB;
      x_3 = modP(dacb * dacb);
      z_3 = modP(x_1 * modP(da_cb * da_cb));
      x_2 = modP(AA * BB);
      z_2 = modP(E * (AA + modP(a24 * E)));
    }
    const mask = cmask(P2, k);
    ({ x_2, x_3 } = swap(mask, x_2, x_3));
    ({ x_2: z_2, x_3: z_3 } = swap(mask, z_2, z_3));
    const z2 = powPminus2(z_2);
    return modP(x_2 * z2);
  }
  const lengths = {
    secretKey: fieldLen,
    publicKey: fieldLen,
    seed: fieldLen
  };
  const randomSecretKey = (seed) => {
    seed = seed === void 0 ? randomBytes_(fieldLen) : seed;
    abytes3(seed, lengths.seed, "seed");
    return seed;
  };
  const utils2 = { randomSecretKey };
  Object.freeze(lengths);
  Object.freeze(utils2);
  return Object.freeze({
    keygen: createKeygen(randomSecretKey, getPublicKey2),
    getSharedSecret: getSharedSecret2,
    getPublicKey: getPublicKey2,
    scalarMult,
    scalarMultBase,
    utils: utils2,
    GuBytes: GuBytes.slice(),
    lengths
  });
}

// node_modules/@noble/curves/ed25519.js
var _0n7 = /* @__PURE__ */ BigInt(0);
var _1n7 = /* @__PURE__ */ BigInt(1);
var _2n5 = /* @__PURE__ */ BigInt(2);
var _3n2 = /* @__PURE__ */ BigInt(3);
var _5n2 = /* @__PURE__ */ BigInt(5);
var _8n3 = /* @__PURE__ */ BigInt(8);
var ed25519_CURVE_p = /* @__PURE__ */ BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
var ed25519_CURVE = /* @__PURE__ */ (() => ({
  p: ed25519_CURVE_p,
  n: BigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
  h: _8n3,
  a: BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"),
  d: BigInt("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"),
  Gx: BigInt("0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"),
  Gy: BigInt("0x6666666666666666666666666666666666666666666666666666666666666658")
}))();
function ed25519_pow_2_252_3(x) {
  const _10n = BigInt(10), _20n = BigInt(20), _40n = BigInt(40), _80n = BigInt(80);
  const P2 = ed25519_CURVE_p;
  const x2 = x * x % P2;
  const b2 = x2 * x % P2;
  const b4 = pow2(b2, _2n5, P2) * b2 % P2;
  const b5 = pow2(b4, _1n7, P2) * x % P2;
  const b10 = pow2(b5, _5n2, P2) * b5 % P2;
  const b20 = pow2(b10, _10n, P2) * b10 % P2;
  const b40 = pow2(b20, _20n, P2) * b20 % P2;
  const b80 = pow2(b40, _40n, P2) * b40 % P2;
  const b160 = pow2(b80, _80n, P2) * b80 % P2;
  const b240 = pow2(b160, _80n, P2) * b80 % P2;
  const b250 = pow2(b240, _10n, P2) * b10 % P2;
  const pow_p_5_8 = pow2(b250, _2n5, P2) * x % P2;
  return { pow_p_5_8, b2 };
}
function adjustScalarBytes(bytes) {
  bytes[0] &= 248;
  bytes[31] &= 127;
  bytes[31] |= 64;
  return bytes;
}
var ED25519_SQRT_M1 = /* @__PURE__ */ BigInt("19681161376707505956807079304988542015446066515923890162744021073123829784752");
function uvRatio(u, v) {
  const P2 = ed25519_CURVE_p;
  const v3 = mod(v * v * v, P2);
  const v7 = mod(v3 * v3 * v, P2);
  const pow3 = ed25519_pow_2_252_3(u * v7).pow_p_5_8;
  let x = mod(u * v3 * pow3, P2);
  const vx2 = mod(v * x * x, P2);
  const root1 = x;
  const root2 = mod(x * ED25519_SQRT_M1, P2);
  const useRoot1 = vx2 === u;
  const useRoot2 = vx2 === mod(-u, P2);
  const noRoot = vx2 === mod(-u * ED25519_SQRT_M1, P2);
  if (useRoot1)
    x = root1;
  if (useRoot2 || noRoot)
    x = root2;
  if (isNegativeLE(x, P2))
    x = mod(-x, P2);
  return { isValid: useRoot1 || useRoot2, value: x };
}
var ed25519_Point = /* @__PURE__ */ edwards(ed25519_CURVE, { uvRatio });
var x25519 = /* @__PURE__ */ (() => {
  const P2 = ed25519_CURVE_p;
  const powPminus2 = (x) => {
    const { pow_p_5_8, b2 } = ed25519_pow_2_252_3(x);
    return mod(pow2(pow_p_5_8, _3n2, P2) * b2, P2);
  };
  return montgomery({
    P: P2,
    type: "x25519",
    powPminus2,
    adjustScalarBytes,
    // ~3x faster fixed-base: [k]B on the birationally-equivalent Edwards curve using cached
    // base tables, mapped back via u = (1+y)/(1-y) = (Z+Y)/(Z-Y) with one Fermat inversion.
    // Same construction as libsodium's crypto_scalarmult_curve25519_base.
    scalarMultBase: (k) => {
      const kn = mod(k, ed25519_Point.Fn.ORDER);
      if (kn === _0n7)
        return _0n7;
      const p = ed25519_Point.BASE.multiply(kn);
      return mod((p.Z + p.Y) * powPminus2(mod(p.Z - p.Y, P2)), P2);
    }
  });
})();

// node_modules/@noble/hashes/hmac.js
var _HMAC = class {
  oHash;
  iHash;
  blockLen;
  outputLen;
  canXOF = false;
  finished = false;
  destroyed = false;
  constructor(hash, key) {
    ahash(hash);
    abytes2(key, void 0, "key");
    this.iHash = hash.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("expected Hash instance");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash.create();
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54 ^ 92;
    this.oHash.update(pad);
    clean(pad);
  }
  update(buf) {
    aexists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const buf = out.subarray(0, this.outputLen);
    this.iHash.digestInto(buf);
    this.oHash.update(buf);
    this.oHash.digestInto(buf);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to ||= Object.create(Object.getPrototypeOf(this), {});
    const { oHash, iHash, finished, destroyed, blockLen, outputLen, canXOF } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.canXOF = canXOF;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
};
var hmac = /* @__PURE__ */ (() => {
  const hmac_ = ((hash, key, message) => new _HMAC(hash, key).update(message).digest());
  hmac_.create = (hash, key) => new _HMAC(hash, key);
  return hmac_;
})();

// node_modules/@noble/hashes/hkdf.js
var HKDF_COUNTER = /* @__PURE__ */ Uint8Array.of(0);
var EMPTY_BUFFER = /* @__PURE__ */ Uint8Array.of();
function expand(hash, prk, info, length = 32, _recycled) {
  ahash(hash);
  anumber(length, "length");
  abytes2(prk, void 0, "prk");
  const olen = hash.outputLen;
  if (prk.length < olen)
    throw new Error('"prk" must be at least HashLen octets');
  if (length > 255 * olen)
    throw new Error("Length must be <= 255*HashLen");
  const blocks = Math.ceil(length / olen);
  if (info === void 0)
    info = EMPTY_BUFFER;
  else
    abytes2(info, void 0, "info");
  if (!blocks) {
    if (_recycled)
      clean(prk);
    return new Uint8Array();
  }
  const okm = _recycled && blocks === 1 ? prk : new Uint8Array(blocks * olen);
  const { iHash, oHash } = hmac.create(hash, prk);
  const T = _recycled ? prk : new Uint8Array(olen);
  const worker = blocks > 1 ? _recycled?.iHash || hash.create() : void 0;
  for (let counter = 0; counter < blocks - 1; counter++) {
    HKDF_COUNTER[0] = counter + 1;
    const iWork = iHash._cloneInto(worker);
    if (counter)
      iWork.update(T);
    iWork.update(info).update(HKDF_COUNTER).digestInto(T);
    oHash._cloneInto(worker).update(T).digestInto(T);
    okm.set(T, olen * counter);
  }
  HKDF_COUNTER[0] = blocks;
  if (blocks > 1)
    iHash.update(T);
  iHash.update(info).update(HKDF_COUNTER).digestInto(T);
  oHash.update(T).digestInto(T);
  okm.set(T, olen * (blocks - 1));
  iHash.destroy();
  oHash.destroy();
  worker?.destroy();
  if (T !== okm)
    clean(T);
  clean(HKDF_COUNTER);
  if (length === okm.length)
    return okm;
  const res = okm.slice(0, length);
  clean(okm);
  return res;
}
var hkdf = (hash, ikm, salt, info, length) => {
  ahash(hash);
  if (salt === void 0)
    salt = new Uint8Array(hash.outputLen);
  const HMAC = hmac.create(hash, salt).update(ikm);
  return expand(hash, HMAC.digest(), info, length, HMAC);
};

// src/aci-e2ee.ts
var ACI_E2EE_VERSION = "2";
var ACI_E2EE_ALGORITHM = "x25519-aes-256-gcm-hkdf-sha256";
var HKDF_INFO = new TextEncoder().encode("aci.e2ee.v2.x25519");
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var NONCE_PATTERN = /^[0-9a-f]{64}$/i;
var HEX_PATTERN = /^(?:[0-9a-f]{2})+$/i;
function secureRandomBytes(length) {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("ACI E2EE needs a secure cryptographic runtime");
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}
function concatBytes4(...arrays) {
  const result = new Uint8Array(arrays.reduce((total, value) => total + value.length, 0));
  let offset = 0;
  for (const value of arrays) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}
function decodeHex(value, label) {
  const clean2 = value.replace(/^0x/i, "");
  if (!HEX_PATTERN.test(clean2)) throw new Error(`${label} must be hexadecimal bytes`);
  return fromHex(clean2);
}
function validateContext(context) {
  const request = context?.purpose === "aci.e2ee.request.v2";
  const response = context?.purpose === "aci.e2ee.response.v2";
  if (!request && !response) throw new Error("Unsupported ACI E2EE field purpose");
  if (typeof context.model !== "string" || !context.model || context.model.length > 256) {
    throw new Error("ACI E2EE context needs a bounded model identifier");
  }
  if (typeof context.field !== "string" || !context.field || context.field.length > 512) {
    throw new Error("ACI E2EE context needs a bounded field identifier");
  }
  if (!NONCE_PATTERN.test(context.nonce)) {
    throw new Error("ACI E2EE context nonce must contain exactly 32 hexadecimal bytes");
  }
  if (!Number.isSafeInteger(context.timestamp) || context.timestamp <= 0) {
    throw new Error("ACI E2EE context needs a positive integer timestamp");
  }
  if (request && context.responseId !== void 0) {
    throw new Error("ACI E2EE request context must not contain a response id");
  }
  if (response && (typeof context.responseId !== "string" || !context.responseId || context.responseId.length > 256)) {
    throw new Error("ACI E2EE response context needs a bounded response id");
  }
}
async function deriveAesKey(sharedSecret) {
  const keyBytes = hkdf(sha256, sharedSecret, void 0, HKDF_INFO, 32);
  try {
    return await globalThis.crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  } finally {
    keyBytes.fill(0);
  }
}
function aciE2eeAad(context) {
  validateContext(context);
  return encoder.encode(
    jcsStringify({
      purpose: context.purpose,
      algo: ACI_E2EE_ALGORITHM,
      model: context.model,
      ...context.responseId === void 0 ? {} : { id: context.responseId },
      field: context.field,
      nonce: context.nonce,
      ts: context.timestamp
    })
  );
}
function createAciE2eeClientKeyPair(options = {}) {
  const secretKey = options.secretKey ? Uint8Array.from(options.secretKey) : secureRandomBytes(32);
  if (secretKey.length !== 32) {
    secretKey.fill(0);
    throw new Error("ACI E2EE client secret must contain exactly 32 bytes");
  }
  try {
    const publicKey = x25519.getPublicKey(secretKey);
    return { secretKey, publicKey, publicKeyHex: toHex(publicKey) };
  } catch (error) {
    secretKey.fill(0);
    throw error;
  }
}
function generateAciE2eeNonce() {
  return toHex(secureRandomBytes(32));
}
async function encryptAciE2eeField(plaintext, recipientPublicKeyHex, context, options = {}) {
  if (typeof plaintext !== "string") throw new TypeError("ACI E2EE plaintext must be a string");
  validateContext(context);
  const recipient = decodeHex(recipientPublicKeyHex, "ACI E2EE recipient key");
  if (recipient.length !== 32) {
    throw new Error("ACI E2EE recipient key must contain exactly 32 bytes");
  }
  const ephemeralSecret = options.ephemeralSecretKey ? Uint8Array.from(options.ephemeralSecretKey) : secureRandomBytes(32);
  const nonce = options.aesNonce ? Uint8Array.from(options.aesNonce) : secureRandomBytes(12);
  if (ephemeralSecret.length !== 32 || nonce.length !== 12) {
    ephemeralSecret.fill(0);
    throw new Error("Invalid ACI E2EE encryption parameters");
  }
  let shared;
  try {
    const ephemeralPublic = x25519.getPublicKey(ephemeralSecret);
    shared = x25519.getSharedSecret(ephemeralSecret, recipient);
    const key = await deriveAesKey(shared);
    const ciphertext = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          additionalData: aciE2eeAad(context),
          tagLength: 128
        },
        key,
        encoder.encode(plaintext)
      )
    );
    return toHex(concatBytes4(ephemeralPublic, nonce, ciphertext));
  } finally {
    ephemeralSecret.fill(0);
    shared?.fill(0);
  }
}
async function decryptAciE2eeField(ciphertextHex, recipientSecretKey, context) {
  validateContext(context);
  const bytes = decodeHex(ciphertextHex, "ACI E2EE response field");
  const secret = Uint8Array.from(recipientSecretKey);
  if (bytes.length < 61 || secret.length !== 32) {
    secret.fill(0);
    throw new Error("ACI E2EE response field is malformed");
  }
  let shared;
  try {
    shared = x25519.getSharedSecret(secret, bytes.slice(0, 32));
    const key = await deriveAesKey(shared);
    const plaintext = await globalThis.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: bytes.slice(32, 44),
        additionalData: aciE2eeAad(context),
        tagLength: 128
      },
      key,
      bytes.slice(44)
    );
    return decoder.decode(plaintext);
  } catch {
    throw new Error("ACI E2EE response authentication failed");
  } finally {
    secret.fill(0);
    shared?.fill(0);
  }
}

// src/index.ts
var DEFAULT_BASE_URL = "https://api.venice.ai";
var DEFAULT_SESSION_TTL = 30 * 60 * 1e3;
function createVeniceE2EE(options) {
  const {
    apiKey,
    baseUrl = DEFAULT_BASE_URL,
    sessionTTL = DEFAULT_SESSION_TTL,
    verifyAttestation: shouldVerify = true,
    dcapVerifier,
    requireDcap = false,
    gpuVerifier,
    requireGpu = false,
    expectedMeasurements,
    allowPlaintextResponses = false
  } = options;
  if (!shouldVerify && (requireDcap || requireGpu || expectedMeasurements)) {
    throw new Error("Attestation policy cannot be required when verifyAttestation is false");
  }
  let _session = null;
  let _pendingSession = null;
  async function fetchAttestation(modelId) {
    const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
    const nonce = toHex(nonceBytes);
    const url = `${baseUrl}/api/v1/tee/attestation?model=${encodeURIComponent(modelId)}&nonce=${nonce}`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${apiKey}` }
    });
    if (!res.ok) throw new Error(`TEE attestation failed (${res.status})`);
    const response = await res.json();
    return { response, nonceBytes };
  }
  async function createSession(modelId) {
    if (_session && _session.modelId === modelId && Date.now() - _session.created < sessionTTL) {
      return _session;
    }
    if (_pendingSession) return _pendingSession;
    _pendingSession = _createSessionInner(modelId);
    try {
      return await _pendingSession;
    } finally {
      _pendingSession = null;
    }
  }
  async function _createSessionInner(modelId) {
    const keypair = generateKeypair();
    const { response, nonceBytes } = await fetchAttestation(modelId);
    const modelPubKeyHex = response.signing_key || response.signing_public_key;
    if (!modelPubKeyHex) {
      throw new Error("No signing key in attestation response");
    }
    let attestation;
    if (shouldVerify) {
      attestation = await verifyAttestation(response, nonceBytes, {
        dcapVerifier,
        requireDcap,
        gpuVerifier,
        requireGpu,
        expectedMeasurements,
        expectedModelId: modelId
      });
      if (attestation.errors.length > 0) {
        throw new Error(
          `TEE attestation verification failed:
  - ${attestation.errors.join("\n  - ")}`
        );
      }
    }
    const aesKey = await deriveAESKey(keypair.privateKey, modelPubKeyHex);
    if (_session) _session.privateKey.fill(0);
    _session = {
      ...keypair,
      modelPubKeyHex,
      aesKey,
      modelId,
      created: Date.now(),
      attestation
    };
    return _session;
  }
  async function encrypt(messages, session) {
    const encryptedMessages = await Promise.all(
      messages.map(async ({ role, content, tool_call_id }) => {
        const encrypted = {
          role,
          content: await encryptMessage(
            session.aesKey,
            session.publicKey,
            flattenMessageContent(content)
          )
        };
        if (role === "tool" && tool_call_id !== void 0) {
          encrypted.tool_call_id = tool_call_id;
        }
        return encrypted;
      })
    );
    return {
      encryptedMessages,
      headers: {
        "X-Venice-TEE-Client-Pub-Key": session.pubKeyHex,
        "X-Venice-TEE-Model-Pub-Key": session.modelPubKeyHex,
        "X-Venice-TEE-Signing-Algo": "ecdsa"
      },
      veniceParameters: { enable_e2ee: true }
    };
  }
  async function decrypt(hexChunk, session) {
    return decryptChunk(session.privateKey, hexChunk, allowPlaintextResponses);
  }
  async function* decryptStream(body, session) {
    yield* decryptSSEStream(body, session.privateKey, allowPlaintextResponses);
  }
  async function fetchResponseSignature(modelId, requestId) {
    const url = `${baseUrl}/api/v1/tee/signature?model=${encodeURIComponent(modelId)}&request_id=${encodeURIComponent(requestId)}`;
    const res = await fetch(url, { headers: { Authorization: `Bearer ${apiKey}` } });
    if (!res.ok) {
      throw new Error(`TEE signature fetch failed (${res.status}): ${await res.text()}`);
    }
    return res.json();
  }
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
    clearSession
  };
}
function isE2EEModel(modelId) {
  return modelId.startsWith("e2ee-");
}
export {
  ACI_ATTESTATION_PATH,
  ACI_E2EE_ALGORITHM,
  ACI_E2EE_VERSION,
  ACI_KEYSET_ENDORSEMENT_PURPOSE,
  ACI_REPORT_DATA_PURPOSE,
  ACI_SESSIONS_PATH,
  BODY_BINDING_CHECKS,
  TOOL_CALL_CLOSE,
  TOOL_CALL_OPEN,
  TOOL_RESPONSE_CLOSE,
  TOOL_RESPONSE_OPEN,
  ToolCallStreamParser,
  aciE2eeAad,
  aciKeysetEndorsementPayload,
  aciReportData,
  aciReportDataStatement,
  buildToolSystemPrompt,
  computeAttestedSessionId,
  computeWorkloadId,
  computeWorkloadKeysetDigest,
  createAciE2eeClientKeyPair,
  createVeniceE2EE,
  decodeSessionEvidence,
  decryptAciE2eeField,
  decryptChunk,
  decryptSSEStream,
  deriveAESKey,
  deriveEthAddress,
  encryptAciE2eeField,
  encryptMessage,
  establishAciTrustAnchor,
  fetchAciAttestation,
  fetchAttestedSession,
  flattenMessageContent,
  fromHex,
  generateAciE2eeNonce,
  generateAciNonce,
  generateKeypair,
  generateToolCallId,
  hashReceiptBody,
  isE2EEModel,
  jcsStringify,
  parseToolCalls,
  receiptSigningBytes,
  recoverReceiptSigner,
  renderToolMessages,
  sha256Prefixed,
  toHex,
  verifyAciAttestation,
  verifyAttestation,
  verifyAttestedSession,
  verifyReceipt,
  verifyRelayedAciAttestation
};
/*! Bundled license information:

@noble/secp256k1/index.js:
  (*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) *)

@noble/curves/utils.js:
@noble/curves/abstract/modular.js:
@noble/curves/abstract/curve.js:
@noble/curves/abstract/edwards.js:
@noble/curves/abstract/montgomery.js:
@noble/curves/ed25519.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
