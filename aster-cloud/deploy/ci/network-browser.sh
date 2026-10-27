#!/usr/bin/env bash
# Run only inside mysql-native.sh's disposable Unix-socket MySQL fixture.
# Secrets, TLS keys, NSS profile, browser diagnostics and credentials stay in the
# private scratch; only allowlisted PNGs and fixed-schema results are exported.
set +x
set -euo pipefail
umask 077
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
[[ $(uname -s) == Linux && $EUID != 0 ]] || fail 'Use the unprivileged disposable Linux runner.'
[[ -n ${ASTER_MYSQL_TEST_DSN:-} && -n ${ASTER_NATIVE_MYSQL_FIXTURE_ROOT:-} ]] || fail 'Disposable native MySQL is required.'
[[ -n ${RUNNER_TEMP:-} && -d $RUNNER_TEMP ]] || fail 'Private runner scratch is required.'
[[ -d ${PLAYWRIGHT_MODULE_DIR:-}/playwright && -d ${PLAYWRIGHT_BROWSERS_PATH:-} ]] || fail 'Pinned private Playwright installation is required.'
for tool in go node python3 openssl certutil curl; do command -v "$tool" >/dev/null || fail "Missing required tool: $tool"; done
node -e 'if(require(process.env.PLAYWRIGHT_MODULE_DIR+"/playwright/package.json").version!=="1.64.0")process.exit(1)' || fail 'Playwright must be exactly 1.64.0.'
cloud=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
ci="$cloud/deploy/ci"
python3 -B "$ci/test_members_browser_contract.py"
node --test "$ci/members-browser.test.mjs"
node --test "$ci/identity-browser.test.mjs"
[[ -f $cloud/frontend/dist/index.html ]] || fail 'Build the real frontend before browser acceptance.'
[[ -f $ci/network-browser.mjs ]] || fail 'The required UI acceptance script is missing.'
scratch=$(mktemp -d "$RUNNER_TEMP/aster-network-browser.XXXXXXXX")
fixture_pid=''
fixture_status=''
fixture_done=false
stop_fixture() {
  [[ -n $fixture_pid && $fixture_done == false ]] || return 0
  touch "$scratch/stop-browser"
  local end=$((SECONDS + 35))
  while kill -0 "$fixture_pid" 2>/dev/null && ((SECONDS < end)); do sleep 0.1; done
  if kill -0 "$fixture_pid" 2>/dev/null; then kill -TERM "$fixture_pid" 2>/dev/null || true; fi
  fixture_status=0
  wait "$fixture_pid" || fixture_status=$?
  fixture_done=true
}
cleanup() {
  local result=$?
  trap - EXIT INT TERM
  stop_fixture
  rm -rf -- "$scratch"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
unset ASTER_CLOUD_TEST_DSN
export ASTER_BROWSER_CI=1 ASTER_BROWSER_CASE="$scratch" ASTER_BROWSER_DIST="$cloud/frontend/dist"
export BASE_URL='https://localhost:5447' BROWSER_CREDENTIALS_FILE="$scratch/browser-credentials.json"
export FIREFOX_PROFILE_DIR="$scratch/firefox-profile"
export BROWSER_ARTIFACT_DIR="$cloud/artifacts/network-browser"
export NO_PROXY='localhost,127.0.0.1,::1' no_proxy='localhost,127.0.0.1,::1'
mkdir -p "$cloud/artifacts"
mkdir "$BROWSER_ARTIFACT_DIR" || fail 'Refuse to mix results with an existing browser artifact directory.'
mkdir "$FIREFOX_PROFILE_DIR"
printf 'PROCESS_START' >"$scratch/fixture-phase"
sanitize_fixture_failure() {
  python3 - "$scratch/fixture.log" "$BROWSER_ARTIFACT_DIR/fixture.json" "$ci/network-browser-fixture.gotxt" "$scratch/fixture-phase" "$1" <<'PYFIXTURE'
import json, pathlib, re, sys
log_path, result_path, source_path, phase_path = map(pathlib.Path, sys.argv[1:5])
reason = sys.argv[5]
assert reason in {'fixture_startup_failed', 'fixture_readiness_timeout', 'fixture_test_failed'}
text = log_path.read_text(errors='replace') if log_path.exists() else ''
source = source_path.read_text().splitlines()
# Export only fixed codes and line numbers from the checked-out source. The
# matching t.Fatal prefix is an allowlist, never copied from the private log.
fatal = {}
for line, content in enumerate(source, 1):
    match = re.search(r'\bt\.Fatalf?\(\s*("(?:[^"\\]|\\.)*")', content)
    if match:
        try: fatal[line] = json.loads(match.group(1))
        except ValueError: pass
locations, calls = [], []
for content in text.splitlines():
    match = re.match(r'^\s*(?:owned_nat_browser_fixture_test\.go|network-browser-fixture\.gotxt):(\d+):\s?(.*)$', content)
    if not match: continue
    line, private_message = int(match.group(1)), match.group(2)
    if not 1 <= line <= len(source): continue
    location = {'source': 'network-browser-fixture.gotxt', 'line': line}
    if line in fatal and private_message.startswith(fatal[line]):
        locations.append({**location, 'code': 'FIXTURE_ASSERTION'})
    elif line not in fatal:
        # t.Helper may report the caller rather than its internal assertion.
        # This is explicitly a source location, not a claimed exact t.Fatal.
        calls.append({**location, 'code': 'FIXTURE_SOURCE_LOCATION'})
unique = []
for item in locations or calls:
    if item not in unique: unique.append(item)
phases = {'PROCESS_START', 'OVERLAY_INITIALIZATION', 'NAT_APPROVAL', 'PARTICIPANT_CAPABILITIES', 'DIRECT_NODE_SETUP', 'DIRECT_POOL_SETUP', 'INITIAL_EPOCH_PLAN', 'INITIAL_EPOCH_RELEASE', 'INITIAL_HISTORY_CAPTURE', 'IDENTITY_SETUP', 'LOOPBACK_LISTENER', 'CREDENTIAL_HANDOFF', 'BROWSER_READY', 'HEARTBEAT_REGRESSION'}
phase = phase_path.read_text().strip() if phase_path.exists() else ''
if phase not in phases: phase = 'UNKNOWN'
checks = {
    'financial/node historical snapshot changed': 'financial_or_node_history_changed',
    'initial network snapshot changed': 'network_history_changed',
    'initial node receipt changed': 'node_receipt_history_changed',
    'required browser plan/reconcile/recovery/VPC persistence did not execute': 'required_browser_operations_missing',
    'durable browser evidence unavailable': 'durable_evidence_unavailable',
    'browser fixture exceeded bounded lifetime': 'fixture_lifetime_exceeded',
    'DATA RACE': 'race_detected',
}
codes = [reason] + [code for fragment, code in checks.items() if fragment in text]
value = {'passed': False, 'codes': codes, 'phase': phase, 'source_locations': unique[-8:]}
result_path.write_text(json.dumps(value, indent=2) + '\n')
print('Backend fixture result: ' + ', '.join(codes) + '; phase=' + phase)
for item in value['source_locations']:
    print(item['code'] + ': ' + item['source'] + ':' + str(item['line']))
PYFIXTURE
}
cat >"$scratch/ca.cnf" <<'CA'
[req]
prompt=no
distinguished_name=subject
x509_extensions=extensions
[subject]
CN=Aster disposable network browser localhost CA
[extensions]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
nameConstraints=critical,permitted;DNS:localhost,permitted;IP:127.0.0.1/255.255.255.255
CA
cat >"$scratch/server.cnf" <<'SERVER'
[req]
prompt=no
distinguished_name=subject
[subject]
CN=localhost
[extensions]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
SERVER
openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 1 -config "$scratch/ca.cnf" -keyout "$scratch/ca.key" -out "$scratch/ca.pem" >"$scratch/openssl.log" 2>&1
openssl req -new -newkey rsa:2048 -nodes -sha256 -config "$scratch/server.cnf" -keyout "$scratch/server.key" -out "$scratch/server.csr" >>"$scratch/openssl.log" 2>&1
openssl x509 -req -sha256 -days 1 -in "$scratch/server.csr" -CA "$scratch/ca.pem" -CAkey "$scratch/ca.key" -CAcreateserial -extfile "$scratch/server.cnf" -extensions extensions -out "$scratch/server.pem" >>"$scratch/openssl.log" 2>&1
# Signing is complete; this CA can no longer issue another certificate.
rm -- "$scratch/ca.key"
python3 - "$cloud" "$scratch" <<'PY'
import json, pathlib, sys
cloud, scratch = map(pathlib.Path, sys.argv[1:])
(scratch / 'go-overlay.json').write_text(json.dumps({'Replace': {
    str(cloud / 'internal/control/owned_nat_browser_fixture_test.go'):
    str(cloud / 'deploy/ci/network-browser-fixture.gotxt'),
    str(cloud / 'internal/control/owned_identity_browser_fixture_test.go'):
    str(cloud / 'deploy/ci/identity-browser-fixture.gotxt')
}}))
PY
(cd "$cloud" && go test -mod=readonly -race -overlay "$scratch/go-overlay.json" -c -o "$scratch/browser.test" ./internal/control)
# First verify the response-fault mechanism over both real TLS protocols. It
# must expose genuine successful headers, then an incomplete JSON body, with
# exactly one server POST; no before-commit race or transport replay is accepted.
"$scratch/browser.test" -test.run '^TestOwnedPublicIPResponseFault$' -test.count=1 -test.v >"$scratch/response-fault.log" 2>&1 || fail 'Public allocation response-fault regression failed; private diagnostics withheld.'
for protocol in http1 http2; do
  grep -q -- "--- PASS: TestOwnedPublicIPResponseFault/$protocol " "$scratch/response-fault.log" || fail 'Both actual TLS response-fault protocols must pass.'
done
if grep -qE -- '--- (SKIP|FAIL):' "$scratch/response-fault.log"; then fail 'Response-fault regression must not skip or fail.'; fi

# Exercise the identical-update failure and genuinely fresh observed/received
# chronology against the same disposable MySQL, never by weakening Heartbeat.
printf 'HEARTBEAT_REGRESSION' >"$scratch/fixture-phase"
if ! (cd "$cloud/internal/control" && "$scratch/browser.test" -test.v -test.count=1 -test.timeout=2m -test.run '^TestOwnedPublicIngressHeartbeatChronology$') >"$scratch/fixture.log" 2>&1; then
  sanitize_fixture_failure fixture_startup_failed
  fail 'Real MySQL heartbeat chronology regression failed; only fixed diagnostics exported.'
fi
grep -q '^--- PASS: TestOwnedPublicIngressHeartbeatChronology ' "$scratch/fixture.log" || fail 'Required real MySQL heartbeat chronology regression did not pass.'
if grep -qE -- '--- (SKIP|FAIL):' "$scratch/fixture.log"; then fail 'Required heartbeat chronology regression must not skip or fail.'; fi
printf 'PASS: real MySQL heartbeat chronology regression; production changedRows guard retained.\n'
printf 'PROCESS_START' >"$scratch/fixture-phase"

(cd "$cloud/internal/control" && exec "$scratch/browser.test" -test.v -test.count=1 -test.timeout=21m -test.run '^TestOwnedNATBrowserFixture$') >"$scratch/fixture.log" 2>&1 &
fixture_pid=$!
ready=false
for ((attempt = 0; attempt < 900; attempt++)); do
  if ! kill -0 "$fixture_pid" 2>/dev/null; then
    stop_fixture
    sanitize_fixture_failure fixture_startup_failed
    fail 'Private browser fixture stopped before readiness; only fixed diagnostics exported.'
  fi
  if [[ -s $BROWSER_CREDENTIALS_FILE ]] && grep -q 'READY: loopback HTTPS' "$scratch/fixture.log"; then ready=true; break; fi
  sleep 0.1
done
if [[ $ready != true ]]; then
  stop_fixture
  sanitize_fixture_failure fixture_readiness_timeout
  fail 'Browser fixture readiness timed out; only fixed diagnostics exported.'
fi
curl --fail --silent --show-error --cacert "$scratch/ca.pem" --resolve localhost:5447:127.0.0.1 --max-time 10 "$BASE_URL/" -o /dev/null
# Only this new private NSS profile gets the CA; never modify host trust or
# browser global policy, and never use ignoreHTTPSErrors or click through TLS.
certutil -N -d "sql:$FIREFOX_PROFILE_DIR" --empty-password
if ! node "$ci/network-browser-tls.mjs" untrusted >"$scratch/tls-negative.log" 2>&1; then fail 'Actual browser did not prove untrusted TLS rejection; raw browser diagnostics withheld.'; fi
certutil -A -d "sql:$FIREFOX_PROFILE_DIR" -n aster-ci-localhost -t 'C,,' -i "$scratch/ca.pem"
if ! node "$ci/network-browser-tls.mjs" trusted >"$scratch/tls-positive.log" 2>&1; then fail 'Private-profile CA did not establish strict browser TLS; raw browser diagnostics withheld.'; fi
browser_status=0
node "$ci/network-browser.mjs" >"$scratch/browser.log" 2>&1 || browser_status=$?
# Always wait for the real backend's post-browser durable-history assertion,
# including when UI checks fail. A screenshot or an accepted POST is not enough.
stop_fixture
if [[ $fixture_status != 0 ]]; then
  sanitize_fixture_failure fixture_test_failed
fi
[[ $browser_status == 0 ]] || fail 'Actual browser UI acceptance failed; inspect sanitized report.json, not private logs.'
[[ $fixture_status == 0 ]] || fail 'Backend durable-history acceptance failed; private fixture logs withheld.'
grep -q '^--- PASS: TestOwnedNATBrowserFixture ' "$scratch/fixture.log" || fail 'Required browser fixture did not pass.'
if grep -qE -- '--- (SKIP|FAIL):' "$scratch/fixture.log"; then fail 'Required browser fixture must never skip or fail.'; fi
python3 - "$scratch/fixture.json" "$BROWSER_ARTIFACT_DIR" "$ci" <<'PY'
import json, pathlib, shutil, sys
source, output = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
sys.path.insert(0, sys.argv[3])
from members_browser_contract import validate_members_browser_report
value = json.loads(source.read_text())
assert value.get('passed') is True
assert type(value.get('members_total')) is int and value['members_total'] == 205
assert value.get('members_unchanged') is True
assert value.get('financial_and_node_snapshots_unchanged') is True
assert value.get('initial_network_snapshot_and_receipts_unchanged') is True
assert value.get('lost_ack_reconciled') is True
assert value.get('node_posts_unique') is True and value.get('node_post_count') == 78
assert value.get('epochs') == 13
assert value.get('public_egress_enabled') is True
assert value.get('public_egress_disabled') is True
assert value.get('pure_internet_reenabled') is True

assert value.get('original_node_post_prefix_count') == 30
assert value.get('original_nat_node_post_prefix_count') == 42
assert value.get('public_ip_operations') == 7
assert value.get('public_ip_lease_count') == 2
assert value.get('total_pool_and_nat_operations') == 8
assert value.get('vm_public_resource_operations') == 9
assert value.get('vm_public_resource_history_count') == 3
assert value.get('direct_node_post_count') == 3
assert value.get('public_ingress_operations') == 3
assert value.get('public_ingress_version_history') == 3
assert value.get('public_ingress_default_deny_move_revoke') is True
assert value.get('public_ingress_immutable_operations') is True
for name in ('floating_bound_moved_unbound', 'floating_reclaimed_reallocated',
             'direct_created_dispatched_detached_reclaimed', 'direct_node3_exact_requests_and_results',
             'global_inventory_exclusive', 'first_seven_epochs_retained'):
    assert value.get(name) is True, 'Required direct/floating durable proof missing'
for name in ('public_pool_created', 'public_pool_extended', 'public_pool_state_managed',
             'public_ip_bound', 'public_ip_unbound_after_all_release_receipts',
             'public_ip_reclaimed_and_reallocated', 'public_ip_lease_history_retained',
             'public_ip_post_commit_ack_lost', 'public_ip_fault_headers_flushed'):
    assert value.get(name) is True, 'Required public IP fixture evidence missing'

report = json.loads((output / 'report.json').read_text())
assert report.get('passed') is True, 'UI report must confirm completion'

for name in ('public_ip_pool_managed', 'public_ip_pool_extended',
             'public_ip_post_commit_ack_reconciled', 'public_ip_bound_and_detached',
             'public_ip_reclaimed_and_reallocated', 'original_five_epochs_preserved'):
    assert report.get(name) is True, 'Required visible public IP workflow missing'
for name in ('floating_bound_moved_unbound', 'floating_reclaimed_reallocated',
             'direct_created_dispatched_detached_reclaimed', 'first_seven_epochs_retained'):
    assert report.get(name) is True, 'Required visible direct/floating workflow missing'
assert len(report.get('public_ip_write_attempts', [])) == 16
assert len(report.get('public_ingress_write_attempts', [])) == 3
assert report.get('public_ingress_configured_default_deny_moved_revoked') is True
assert report.get('public_ingress_immutable_operations') is True
business_screenshots = report.get('screenshots', [])
assert len(business_screenshots) == len(set(business_screenshots)) == 52, 'Original 52 actual business screenshots must remain complete'
required_sidebar = {
    'sidebar-320-top.png', 'sidebar-320-drawer.png',
    'sidebar-390-bottom.png', 'sidebar-390-drawer.png',
    'sidebar-768-drawer.png', 'sidebar-1024-drawer.png',
    'sidebar-1025-middle.png', 'sidebar-1440-bottom.png',
    'sidebar-1440-short-nav-bottom.png', 'sidebar-1025-short-nav-bottom.png',
    'sidebar-zoom-720-drawer.png', 'sidebar-zoom-512-drawer.png',
}
sidebar_screenshots = report.get('sidebar_screenshots', [])
assert len(sidebar_screenshots) == 12 and set(sidebar_screenshots) == required_sidebar, 'All 12 responsive sidebar screenshots are mandatory'
assert not set(business_screenshots) & required_sidebar, 'Sidebar evidence cannot replace original business screenshots'
required_members = validate_members_browser_report(report, output)
assert not required_members & (set(business_screenshots) | required_sidebar), 'Members evidence must not replace the original 64 PNG files'
assert {p.name for p in output.glob('*.png')} == set(business_screenshots) | required_sidebar | required_members, 'Exact 70 actual PNG files must match three disjoint report lists'
assert len(report.get('checks', [])) >= 163, 'Original business coverage and the new mobile public-pool layout proof must not be reduced'
pool_heading = [c for c in report.get('checks', []) if c.get('name') == '390px and 320px public pool heading actions fill a row with single-line 44px buttons']
assert len(pool_heading) == 1, 'The actual two-viewport public-pool heading proof is mandatory'
assert [v.get('width') for v in pool_heading[0].get('viewports', [])] == [390, 320]
for proof in pool_heading[0]['viewports']:
    assert proof.get('document_scroll_width', float('inf')) <= proof['width']
    assert proof.get('fills_heading_content') is True and proof.get('below_heading_text') is True
    assert abs(proof['actions_width'] - proof['heading_content_width']) <= 1
    buttons = proof.get('buttons', [])
    assert len(buttons) == 2
    assert abs(buttons[0]['top'] - buttons[1]['top']) <= 1 and abs(buttons[0]['bottom'] - buttons[1]['bottom']) <= 1
    for button in buttons:
        assert button.get('width', 0) >= 44 and button.get('height', 0) >= 44
        assert all(button.get(k) is True for k in ('rendered', 'in_actions_and_viewport', 'has_text', 'text_within_button'))
        assert button.get('text_lines') == 1
assert report.get('console_errors') == [], 'The real browser must not have JavaScript errors'
sidebar_checks = report.get('sidebar_checks', [])
assert len(sidebar_checks) >= 53, 'New command-rail geometry, semantics and navigation lifecycle must all execute'
for mode, count in (('chinese-light', 37), ('english-dark', 16)):
    entries = [c for c in sidebar_checks if c.get('mode') == mode]
    assert len(entries) >= count, 'Both language/theme sidebar matrices must execute'
    for name in ('1024 to 1025 closes drawer, clears inert/history and focuses main',
                 'focused desktop sidebar becomes a reachable compact menu at 1024px',
                 'visible drawer navigation closes the overlay and reaches the actual route',
                 '1440px 360px short-screen independent scroll and keyboard access',
                 '1025px 360px short-screen independent scroll and keyboard access',
                 'visible skip-link click focuses main without changing the hash route or making a write',
                 'single command rail has six real semantic route anchors and controlled compact disclosure'):
        assert any(c.get('name') == name for c in entries), 'A required sidebar geometry/lifecycle proof is missing'
    for width in (1440, 1025):
        proof = next(c for c in entries if c.get('name') == str(width) + 'px 360px short-screen independent scroll and keyboard access')
        targets = proof.get('keyboard_targets', [])
        assert len(targets) == 7, 'Every actual sidebar link and sign-out must retain exact keyboard geometry proof'
        assert [t.get('link_index') for t in targets[:6]] == list(range(6)) and targets[-1].get('logout') is True
        for target in targets:
            assert all(target.get('checks', {}).get(k) is True for k in ('focused', 'visible', 'target_size', 'in_viewport', 'in_clip', 'hit'))
            assert abs(target['document_scroll_y'] - proof['keyboard_document_scroll_y']) <= 1, 'Keyboard sidebar navigation must not move the document'
        assert all(proof.get('preferences_keyboard_target', {}).get('checks', {}).get(k) is True for k in ('focused', 'visible', 'target_size', 'in_viewport', 'in_clip', 'hit')), 'Appearance must also have a real reachable 44px keyboard target'
assert report.get('public_ip_failed_writes') == [{'method': 'POST', 'path': '/console/v1/public-ips/leases'}], 'Only the single original allocation transport fault is permitted'

for path in output.iterdir():
    assert path.is_file() and not path.is_symlink()
    assert path.suffix == '.png' or path.name in {'report.json', 'tls.json'}, 'Artifact is not allowlisted'
shutil.copyfile(source, output / 'fixture.json')
PY
printf 'PASS: actual desktop/mobile browser with strict TLS, real MySQL, UI plan/reconcile/recovery and immutable history. Node RPC is simulated; this is not KVM/dataplane acceptance.\n'

# W07-B has its OWN database and result contract. Do not permit account writes
# in, or remove the history digest from, the original 205-member read-only gate.
export BROWSER_ARTIFACT_DIR="$cloud/artifacts/network-browser/identity"
mkdir "$BROWSER_ARTIFACT_DIR" || fail 'Refuse to mix identity browser evidence.'
rm -- "$scratch/stop-browser" "$scratch/browser-credentials.json"
fixture_done=false
fixture_status=''
(cd "$cloud/internal/control" && exec "$scratch/browser.test" -test.v -test.count=1 -test.timeout=10m -test.run '^TestOwnedIdentityBrowserFixture$') >"$scratch/identity-fixture.log" 2>&1 &
fixture_pid=$!
ready=false
for ((attempt=0;attempt<900;attempt++)); do
  if ! kill -0 "$fixture_pid" 2>/dev/null; then break; fi
  if [[ -s $BROWSER_CREDENTIALS_FILE ]] && grep -q 'READY: identity loopback HTTPS' "$scratch/identity-fixture.log"; then ready=true; break; fi
  sleep 0.1
done
[[ $ready == true ]] || fail 'Independent identity fixture did not become ready; private diagnostics withheld.'
# The same one-day localhost certificate and ONLY the disposable NSS profile
# remain in use. No additional host trust, TLS exception or public listener.
curl --fail --silent --show-error --cacert "$scratch/ca.pem" --resolve localhost:5447:127.0.0.1 --max-time 10 "$BASE_URL/" -o /dev/null
identity_browser_status=0
node "$ci/identity-browser.mjs" >"$scratch/identity-browser.log" 2>&1 || identity_browser_status=$?
stop_fixture
[[ $identity_browser_status == 0 ]] || fail 'Identity browser acceptance failed; inspect only its sanitized report.json.'
[[ $fixture_status == 0 ]] || fail 'Independent identity durable-history acceptance failed; private diagnostics withheld.'
grep -q '^--- PASS: TestOwnedIdentityBrowserFixture ' "$scratch/identity-fixture.log" || fail 'Required identity fixture did not pass.'
if grep -qE -- '--- (SKIP|FAIL):' "$scratch/identity-fixture.log"; then fail 'Identity fixture must never skip or fail.'; fi
cp -- "$scratch/identity-fixture.json" "$BROWSER_ARTIFACT_DIR/fixture.json"
node "$ci/identity-browser-contract.mjs" "$BROWSER_ARTIFACT_DIR"
