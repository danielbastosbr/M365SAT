#!/usr/bin/env bash
# Regenerates docs/CIS-GAP-v7.md. Requires python3 and git (network access to github.com).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${1:-$(mktemp -d)}"
if [ ! -d "$WORK/ext/prowler" ]; then
  mkdir -p "$WORK/ext"
  git clone -q --depth 1 --filter=blob:none --sparse https://github.com/prowler-cloud/prowler.git "$WORK/ext/prowler"
  git -C "$WORK/ext/prowler" sparse-checkout set prowler/compliance/m365 prowler/compliance/azure
fi
python3 -I "$ROOT/tools/cis-gap/extract.py" "$ROOT" "$WORK"
python3 -I "$ROOT/tools/cis-gap/gap.py" "$WORK" > "$WORK/gap.log"
python3 -I "$ROOT/tools/cis-gap/report.py" "$WORK" "$ROOT/docs/CIS-GAP-v7.md"
