#!/usr/bin/env bash
# Fixed test entrypoint for agent-first-files.
#
# The single source of truth for how this spore is tested. CI, the monorepo
# driver (scripts/projects.sh test agent-first-files), and the release gate all
# call this file, so a mode can never mean one thing locally and another in CI.
set -euo pipefail

_AFDATA_BASH_SOURCE="$("${AFDATA_BIN:-afdata}" shell bash)"
# shellcheck source=/dev/stdin
source /dev/stdin <<<"$_AFDATA_BASH_SOURCE"
unset _AFDATA_BASH_SOURCE

ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_PATH"

afdata_args_begin "$0 [MODE]"
afdata_args_positional test_mode MODE "Test mode" optional
afdata_args_parse "$@"
MODE="${test_mode:-all}"
TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/agent-first-files-test.XXXXXX")"
trap 'rm -rf "$TEST_TMP"' EXIT

run_clippy() {
  afdata_run --quiet cargo clippy --all-targets "$@" -- -D warnings
}

# Both tiers, because the featureless one is what a library consumer takes and
# the default build has axum in it — a server crate leaking back into the core
# would compile here and nowhere else would say so.
run_static() {
  # Parsing is not linting, and this ran neither until now. The pinned version
  # lives in the script itself, mirrored from the monorepo and compared byte for
  # byte there, so this spore and its siblings cannot drift onto different rules.
  "$ROOT_PATH/scripts/install-shellcheck.sh" --check "$ROOT_PATH"
  afdata_run --quiet cargo fmt --all --check
  run_clippy
  # Every tier a consumer can ask for, because a tier nothing builds is a tier
  # that compiles by accident.
  run_clippy --features watch
  run_clippy --features api
}

run_unit() {
  afdata_run --quiet node tests/ui_fragment.mjs
  afdata_run --quiet cargo test --all-targets
  afdata_run --quiet cargo test --all-targets --features watch
  afdata_run --quiet cargo test --all-targets --features api
  afdata_run --quiet cargo test --doc --features api
  check_core_tier_dependencies
}

# The core tier's whole point is what it does *not* pull in. A consumer embeds
# `FileRoot` to project a directory; it must not acquire an HTTP server, an
# async runtime, or a platform filesystem-watching backend by doing so.
check_core_tier_dependencies() {
  local tree dependency
  tree="$(cargo tree --edges normal --prefix none)"
  for dependency in axum tokio agent-first-ui minijinja notify async-stream; do
    if [[ "$tree" == *"$dependency v"* ]]; then
      afdata_error unexpected_dependency \
        "$dependency must not be present in the default dependency tree" \
        "keep it behind the api feature" || :
      return 1
    fi
  done
}

# The generated contract is committed, so it goes stale the moment a component
# changes — including on a release bump, which rewrites the version inside it.
check_contract_drift() {
  local exported="$TEST_TMP/openapi"
  afdata_run --quiet cargo run --quiet --features api --bin affiles -- \
    api export --directory "$exported" --force
  if ! diff -ru "$ROOT_PATH/openapi" "$exported" >"$TEST_TMP/contract.diff" 2>&1; then
    afdata_error contract_drift \
      "the committed OpenAPI contract does not match the one this build generates" \
      "run: affiles api export --directory openapi --force" || :
    cat "$TEST_TMP/contract.diff" >&2
    return 1
  fi
}

# The confinement rules through the real binary, because every one of them is a
# claim about what a request from outside can reach — and a unit test proves the
# library refuses, not that the process does.
run_smoke() {
  local binary="$ROOT_PATH/target/debug/affiles"
  local workspace="$TEST_TMP/workspace"
  local outside="$TEST_TMP/outside"
  local log="$TEST_TMP/serve.jsonl"
  local token="affiles-smoke-token-0123456789-abcdef"
  local serve_pid url status body

  afdata_run --quiet cargo build --quiet --features api --bin affiles
  mkdir -p "$workspace/src" "$outside"
  printf '# hello\n' >"$workspace/README.md"
  printf 'TOKEN=1\n' >"$workspace/.env"
  printf 'not yours\n' >"$outside/secret"
  ln -s "$outside/secret" "$workspace/escape"

  AFFILES_API_ACCESS_TOKEN_SECRET="$token" "$binary" api serve \
    --root "$workspace" --port 0 --exclude '.env' >"$log" 2>&1 &
  serve_pid=$!
  # shellcheck disable=SC2064
  trap "kill $serve_pid 2>/dev/null || true; rm -rf '$TEST_TMP'" EXIT

  for _ in $(seq 1 50); do
    [ -s "$log" ] && break
    sleep 0.1
  done
  head -n 1 "$log" >"$TEST_TMP/ready.json"
  url="$(afdata value "$TEST_TMP/ready.json" progress.api_url --default "")"
  if [ -z "$url" ]; then
    afdata_error serve_not_started "affiles api serve did not report a URL" "inspect $log" || :
    return 1
  fi

  # Discovery is public; everything about the root is not.
  for path in /health /openapi.json /schemas/index.json; do
    status="$(curl -sS -o /dev/null -w '%{http_code}' "$url$path")"
    [ "$status" = "200" ] || {
      afdata_error discovery_unavailable "$path answered $status, expected 200" || :
      return 1
    }
  done
  status="$(curl -sS -o /dev/null -w '%{http_code}' "$url/v1/root")"
  [ "$status" = "401" ] || {
    afdata_error unauthenticated_allowed "/v1/root answered $status without a credential" || :
    return 1
  }
  # A credential in the query string is not a credential.
  status="$(curl -sS -o /dev/null -w '%{http_code}' "$url/v1/root?token=$token")"
  [ "$status" = "401" ] || {
    afdata_error query_credential_accepted "a query-string token answered $status" || :
    return 1
  }

  body="$(curl -sS -H "Authorization: Bearer $token" "$url/v1/directories?path=")"
  printf '%s' "$body" >"$TEST_TMP/listing.json"
  case "$body" in
    *README.md*) ;;
    *)
      afdata_error listing_incomplete "the root listing does not contain README.md" || :
      return 1
      ;;
  esac
  # Excluded entries are absent, not refused-with-a-reason.
  case "$body" in
    *.env*)
      afdata_error excluded_entry_listed "an --exclude match appears in a listing" || :
      return 1
      ;;
  esac

  # Every refusal that must be indistinguishable from an absence, asserted by
  # its exact code rather than by "it failed somehow".
  local -a refused=(
    "/v1/files/text?path=.env|404|entry_not_found"
    "/v1/files/text?path=escape|404|entry_not_found"
    "/v1/files/text?path=nope|404|entry_not_found"
    "/v1/files/text?path=../outside/secret|400|invalid_path"
    "/v1/files/text?path=/etc/passwd|400|invalid_path"
  )
  local case_line request expected_status expected_code code
  for case_line in "${refused[@]}"; do
    request="${case_line%%|*}"
    expected_status="$(printf '%s' "$case_line" | cut -d'|' -f2)"
    expected_code="${case_line##*|}"
    status="$(curl -sS -o "$TEST_TMP/refused.json" -w '%{http_code}' \
      -H "Authorization: Bearer $token" "$url$request")"
    code="$(afdata value "$TEST_TMP/refused.json" error.code --default "")"
    if [ "$status" != "$expected_status" ] || [ "$code" != "$expected_code" ]; then
      afdata_error confinement_broken \
        "$request answered $status/$code, expected $expected_status/$expected_code" || :
      return 1
    fi
  done

  kill "$serve_pid" 2>/dev/null || true
  wait "$serve_pid" 2>/dev/null || true
  # shellcheck disable=SC2064
  trap "rm -rf '$TEST_TMP'" EXIT
}

case "$MODE" in
  static)   run_static ;;
  unit)     run_unit ;;
  contract) check_contract_drift ;;
  smoke)    run_smoke ;;
  all)      run_static; run_unit; check_contract_drift; run_smoke ;;
  *)
    afdata_error cli_error "unsupported test mode '$MODE'" \
      "try: $0 static|unit|contract|smoke|all" || :
    exit 2
    ;;
esac

afdata_result "agent-first-files tests complete [$MODE]"
