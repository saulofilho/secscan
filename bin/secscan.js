#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const tsxDir = path.dirname(require.resolve('tsx/package.json'));
const tsxCli = path.join(tsxDir, 'dist', 'cli.mjs');
const entry = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/cli/secscan.ts');
const result = spawnSync(process.execPath, [tsxCli, entry, ...process.argv.slice(2)], {
  stdio: 'inherit',
});

process.exit(result.status === null ? 1 : result.status);
