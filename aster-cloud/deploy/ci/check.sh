#!/usr/bin/env bash
# Called only inside the existing disposable native-MySQL fixture.
set +x
set -euo pipefail
umask 077
[[ -n ${ASTER_MYSQL_TEST_DSN:-} || -n ${ASTER_CLOUD_TEST_DSN:-} ]] || { echo 'A disposable MySQL test DSN is required.' >&2; exit 1; }
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$repo"
scratch=$(mktemp -d "${RUNNER_TEMP:-/tmp}/aster-cloud-check.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
# Independent installer SQL/grants contract. This script rejects missing or
# mismatched native fixture paths; there is deliberately no host-DB fallback.
python3 -B "$repo/deploy/ci/test_cloud_mysql_grants.py" | tee "$scratch/mysql-grants.json"
# No credential is echoed. SQL fixtures accept only explicitly named test DBs.
# The protected-policy connector case genuinely requires root ownership. Run it
# separately below, rather than adding an owner bypass or tolerating a skipped
# MySQL acceptance case. The independently required native OVS matrix is routed
# explicitly below; all other tests still run with race instrumentation.
root_tls='^TestRootTLSConnectorUsesExistingProtectedTransport$'
# Parser/encoder and isolated namespace packet tests require distribution tools
# and privileges. Both run without skips in their required Ubuntu22/24 matrices.
separate_native='^(TestRootTLSConnectorUsesExistingProtectedTransport|TestNativeOVSParserFlows|TestNativeOVSParserMeters|TestNativeNATPacketFlowAndRevocation|TestNativeNATInternetEgressAndRevocation)$'
go test -mod=readonly -race -count=1 -v -skip "$separate_native" -timeout=10m ./... | tee "$scratch/tests.log"
if grep -q -- '--- SKIP:' "$scratch/tests.log"; then
  echo 'MySQL acceptance must not skip any test.' >&2; exit 1
fi
go test -mod=readonly -race -c -o "$scratch/connector.test" ./plugins/billingconnector
if [[ $(id -u) == 0 ]]; then
  "$scratch/connector.test" -test.v -test.run "$root_tls" | tee "$scratch/root-tls.log"
else
  sudo -- "$scratch/connector.test" -test.v -test.run "$root_tls" | tee "$scratch/root-tls.log"
fi
grep -q -- '^--- PASS: TestRootTLSConnectorUsesExistingProtectedTransport ' "$scratch/root-tls.log"
if grep -qE -- '--- (SKIP|FAIL):' "$scratch/root-tls.log"; then
  echo 'Protected root TLS acceptance must not skip or fail.' >&2; exit 1
fi
go vet -mod=readonly ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -buildvcs=false -o "$scratch/aster-controller" ./cmd/aster-controller
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -buildvcs=false -o "$scratch/aster-node" ./cmd/aster-node
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -buildvcs=false -o "$scratch/aster-network" ./cmd/aster-network
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -buildvcs=false -o "$scratch/aster-billing-plugin" ./cmd/aster-billing-plugin
# These checks do not install libvirt, start a node daemon, or create a VM.
echo 'PASS: controller/node Go, real MySQL and static Linux builds; not a real KVM guest acceptance.'
