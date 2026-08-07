import { describe, expect, it } from 'vitest';

import { createDcapVerifier } from './dcap.js';

const compatibilityMode = process.env.DCAP_COMPAT_TEST === '1';

async function captureInvalidQuoteFailure(): Promise<Error | null> {
  try {
    await createDcapVerifier('https://pccs.invalid')(new Uint8Array());
    return null;
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error));
  }
}

describe.skipIf(compatibilityMode)('optional DCAP peer', () => {
  it('explains how to enable verification when the peer is absent', async () => {
    const error = await captureInvalidQuoteFailure();

    expect(error?.message).toBe(
      '@phala/dcap-qvl is required for DCAP verification. Install it: npm install @phala/dcap-qvl'
    );
  });
});

describe.skipIf(!compatibilityMode)('DCAP QVL 0.6 compatibility', () => {
  it('loads and invokes the supported verifier API', async () => {
    const error = await captureInvalidQuoteFailure();

    expect(error).toBeInstanceOf(Error);
    expect(error?.message).not.toContain('@phala/dcap-qvl is required');
    expect(error?.message).not.toMatch(/is not a function/i);
    expect(error?.message).toMatch(/buffer|bounds|length|quote/i);
  });
});
