#!/usr/bin/env bash
# RD-P13 quality matrix — cafe-documentation (docs-only; no Go/npm runtime)
set -euo pipefail
cd "$(dirname "$0")/.."

FAIL=0

echo "==> markdown presence (core guides)"
for f in \
  README.md \
  docs/security/cp-persist-v1.md \
  docs/security/cpm-contract.md \
  docs/architecture/cpm-v1-flow.md \
  02-cafe-user-guide.md \
  03-cafe-developer-guide.md \
  04-cafe-admin-guide.md \
  functional-specifications.md \
  technical-specifications.md
do
  if [[ ! -f "$f" ]]; then
    echo "FAIL: missing $f" >&2
    FAIL=1
  else
    echo "OK: $f"
  fi
done

echo "==> required normative anchors"
check_contains() {
  local file="$1"
  local pat="$2"
  if ! rg -q --fixed-strings "$pat" "$file"; then
    echo "FAIL: $file missing required text: ${pat}" >&2
    FAIL=1
  else
    echo "OK: $file contains [${pat}]"
  fi
}

check_contains docs/security/cp-persist-v1.md "POST /api/cpm/v1/policies"
check_contains docs/security/cp-persist-v1.md "payload_sha256"
check_contains docs/security/cp-persist-v1.md "SCAN_NOT_LATEST"
check_contains docs/security/cp-persist-v1.md "NB1"
check_contains docs/security/cp-persist-v1.md "NB2"
check_contains docs/security/cp-persist-v1.md "ADR_20260824_remove_cp_drafts"
check_contains docs/security/cp-persist-v1.md "openapi/cpm-v1.yaml"
check_contains docs/architecture/cpm-v1-flow.md "POST /policies"
check_contains docs/security/cpm-contract.md "WALLET_CONTROL_PROOF_REQUIRED"
check_contains 03-cafe-developer-guide.md "POST /api/cpm/v1/policies"
check_contains README.md "ADR_20260824_remove_cp_drafts"

echo "==> dead draft surface sweep (normative live paths)"
# Fail if a markdown line mentions a draft surface without a removal/absence marker.
is_removal_context() {
  echo "$1" | rg -qi \
    'removed|supersede|no [`*]*save draft|no save draft|\*\*no\*\* save draft|not an api|do not use|retired|stale client|historical|no shim|dropped|-- crypto_policy_drafts|rd-p14|archaeology|formal amend|  - comments:|versioning|other draft-centric|post\|get\|delete|/drafts\*|\|GET\|DELETE|no `/drafts|no /drafts|not `/drafts|there is \*\*no\*\*|no server draft|client only|nb2|local composition'
}

SURFACES=(
  'POST /api/cpm/v1/drafts'
  'GET /api/cpm/v1/drafts'
  'DELETE /api/cpm/v1/drafts'
  'drafts/{draft_id}/persist'
  'drafts/{id}/persist'
  'DRAFT_ALREADY_PERSISTED'
  'Save draft'
  'Rebind to last scan'
)

while IFS= read -r -d '' file; do
  case "$file" in
    *cafe-mbse-sysml*) continue ;;
  esac
  for surface in "${SURFACES[@]}"; do
    while IFS= read -r line; do
      if is_removal_context "$line"; then
        continue
      fi
      echo "FAIL: live-looking draft surface in $file: $line" >&2
      FAIL=1
    done < <(rg -n --fixed-strings "$surface" "$file" || true)
  done
done < <(find . -name '*.md' -not -path './coverage/*' -not -path './.git/*' -print0)

echo "==> no crypto_policy_drafts as live table (except drop notes)"
while IFS= read -r hit; do
  if is_removal_context "$hit"; then
    continue
  fi
  echo "FAIL: crypto_policy_drafts still presented as live: $hit" >&2
  FAIL=1
done < <(rg -n 'crypto_policy_drafts' --glob '*.md' || true)

echo "==> internal markdown link targets exist"
while IFS= read -r -d '' file; do
  while IFS= read -r link; do
    target="${link#*](}"
    target="${target%%)*}"
    target="${target%%#*}"
    [[ -z "$target" || "$target" == http* || "$target" == mailto:* ]] && continue
    dir="$(dirname "$file")"
    resolved="$dir/$target"
    if [[ ! -e "$resolved" ]]; then
      echo "FAIL: broken relative link in $file → $target" >&2
      FAIL=1
    fi
  done < <(rg -oN '\]\(\./[^)]+\)|\]\(\.\./[^)]+\)' "$file" || true)
done < <(find . -name '*.md' -not -path './coverage/*' -not -path './.git/*' -print0)

if [[ "$FAIL" -ne 0 ]]; then
  echo "==> RD-P13 matrix FAIL" >&2
  exit 1
fi
echo "==> RD-P13 matrix green (docs-only; no govulncheck/deadcode)"
