import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    env: Object.fromEntries(
      (await import('fs'))
        .readFileSync('.env', 'utf-8')
        .split('\n')
        .filter((l: string) => l && !l.startsWith('#'))
        .map((l: string) => l.split('='))
        .map(([k, ...v]: string[]) => [k.trim(), v.join('=').trim()])
    ),
  },
});
