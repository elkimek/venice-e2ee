import { describe, expect, it } from 'vitest';
import { createVeniceE2EE } from './index.js';

describe('createVeniceE2EE policy configuration', () => {
  it('rejects a required DCAP policy when verification is disabled', () => {
    expect(() => createVeniceE2EE({
      apiKey: 'test-key',
      verifyAttestation: false,
      requireDcap: true,
    })).toThrow('Attestation policy cannot be required');
  });

  it('rejects a measurement policy when verification is disabled', () => {
    expect(() => createVeniceE2EE({
      apiKey: 'test-key',
      verifyAttestation: false,
      expectedMeasurements: { mrTd: '0'.repeat(96) },
    })).toThrow('Attestation policy cannot be required');
  });
});
