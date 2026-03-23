import { defineConfig } from 'vitest/config';
import { readFileSync } from 'fs';

function loadEnv(): Record<string, string> {
  try {
    return Object.fromEntries(
      readFileSync('.env', 'utf-8')
        .split('\n')
        .filter((l: string) => l && !l.startsWith('#'))
        .map((l: string) => l.split('='))
        .map(([k, ...v]: string[]) => [k.trim(), v.join('=').trim()])
    );
  } catch {
    return {};
  }
}

export default defineConfig({
  test: {
    env: loadEnv(),
  },
});
