import { describe, expect, it } from 'vitest';
import { stripTrailingSlashes } from './url.js';

describe('stripTrailingSlashes', () => {
  it('removes every trailing slash', () => {
    expect(stripTrailingSlashes('https://tee.example///')).toBe('https://tee.example');
    expect(stripTrailingSlashes('////')).toBe('');
  });

  it('preserves a long non-trailing slash run without regex backtracking', () => {
    const value = `https://tee.example/${'/'.repeat(50_000)}suffix`;
    expect(stripTrailingSlashes(value)).toBe(value);
  });
});
