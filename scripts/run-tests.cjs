'use strict';
// Offline public-source checks only: syntax, rule-document schema, and synthetic tests.
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');

function list(dir, suffix) {
  return fs.readdirSync(path.join(root, dir)).filter((name) => name.endsWith(suffix)).sort().map((name) => path.join(dir, name));
}

function run(args, label = args.join(' ')) {
  const result = spawnSync(process.execPath, args, { cwd: root, stdio: 'inherit' });
  if (result.status !== 0) {
    console.error(`Failed: ${label}`);
    process.exit(result.status ?? 1);
  }
}

const scripts = list('scripts', '.cjs');
const tests = list('tests', '.cjs');
for (const file of [...scripts, ...tests]) run(['--check', file], `node --check ${file}`);
run(['scripts/validate-rules.cjs']);
run(['scripts/Controle-Email.cjs', '--self-test']);
run(['scripts/Controle-Email.cjs', '--evaluate']);
for (const file of tests) run([file]);
console.log(`All checks passed (${scripts.length} scripts syntax-checked, ${tests.length} test files).`);
