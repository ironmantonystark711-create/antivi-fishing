#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
command -v node >/dev/null
command -v python3 >/dev/null
node scripts/check.mjs
node --test --test-concurrency=1 tests/*.test.mjs
node scripts/simulate.mjs
node scripts/verify-export.mjs reports/sample-audit.json reports/sample-pinned-trust.json
node scripts/verify-export-webcrypto.mjs reports/sample-audit.json reports/sample-pinned-trust.json
python3 scripts/canonical-vectors.py examples/canonical-vectors.json
printf '%s\n' 'Engineering checks passed. Production acceptance is a separate gate and is expected to remain BLOCKED.'
