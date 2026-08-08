#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/veil-installer-test.XXXXXX")
cleanup() {
	find "$test_dir" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$test_dir/release" "$test_dir/package" "$test_dir/bin"
go build -o "$test_dir/package/veil" "$project_dir/cmd/veil"
tar -czf "$test_dir/release/veil-linux-amd64.tar.gz" -C "$test_dir/package" veil
(cd "$test_dir/release" && sha256sum veil-linux-amd64.tar.gz > checksums.txt)

VEIL_VERSION=v-test \
VEIL_RELEASE_BASE_URL="file://$test_dir/release" \
VEIL_INSTALL_DIR="$test_dir/bin" \
	sh "$project_dir/install.sh"

test -x "$test_dir/bin/veil"
test "$($test_dir/bin/veil version)" = "veil/dev"
echo "installer test passed"
