#!/bin/sh
set -eu

repository=${VEIL_REPOSITORY:-422dev/veil}
install_relay=0
requested_version=${VEIL_VERSION:-}

usage() {
	cat <<'EOF'
Veil installer for Linux

Usage:
  curl -fsSL https://raw.githubusercontent.com/422dev/veil/main/install.sh | sh
  curl -fsSL https://raw.githubusercontent.com/422dev/veil/main/install.sh | sh -s -- --relay

Options:
  --relay          install veil-relay in addition to the client
  --version TAG    install a specific release, such as v0.1.0
  --help           show this help

Environment:
  VEIL_INSTALL_DIR       destination directory (default: $HOME/.local/bin)
  VEIL_VERSION           release tag to install
  VEIL_REPOSITORY        GitHub owner/repository (default: 422dev/veil)
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--relay)
			install_relay=1
			shift
			;;
		--version)
			[ "$#" -ge 2 ] || { echo "veil installer: --version requires a value" >&2; exit 2; }
			requested_version=$2
			shift 2
			;;
		--help|-h)
			usage
			exit 0
			;;
		*)
			echo "veil installer: unknown option: $1" >&2
			exit 2
			;;
	esac
done

[ "$(uname -s)" = "Linux" ] || { echo "veil installer: only Linux is supported" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "veil installer: curl is required" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "veil installer: tar is required" >&2; exit 1; }

case "$(uname -m)" in
	x86_64|amd64) architecture=amd64 ;;
	aarch64|arm64) architecture=arm64 ;;
	*) echo "veil installer: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ -z "${HOME:-}" ] && [ -z "${VEIL_INSTALL_DIR:-}" ]; then
	echo "veil installer: HOME or VEIL_INSTALL_DIR must be set" >&2
	exit 1
fi
install_dir=${VEIL_INSTALL_DIR:-"$HOME/.local/bin"}

github_url="https://github.com/${repository}"
if [ -z "$requested_version" ]; then
	effective_url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$github_url/releases/latest")
	requested_version=${effective_url##*/}
fi

case "$requested_version" in
	""|*[!A-Za-z0-9._-]*)
		echo "veil installer: invalid release version" >&2
		exit 1
		;;
esac

release_base=${VEIL_RELEASE_BASE_URL:-"$github_url/releases/download/$requested_version"}
temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/veil-install.XXXXXX")
cleanup() {
	find "$temporary_dir" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

download() {
	asset=$1
	curl -fL --proto '=https' --tlsv1.2 "$release_base/$asset" -o "$temporary_dir/$asset"
}

# A file:// override is used only by the repository's offline installer test.
if [ "${VEIL_RELEASE_BASE_URL:-}" != "" ]; then
	download() {
		asset=$1
		curl -fL "$release_base/$asset" -o "$temporary_dir/$asset"
	}
fi

download checksums.txt
client_archive="veil-linux-${architecture}.tar.gz"
download "$client_archive"
if [ "$install_relay" -eq 1 ]; then
	relay_archive="veil-relay-linux-${architecture}.tar.gz"
	download "$relay_archive"
fi

verify_asset() {
	asset=$1
	expected=$(awk -v name="$asset" '$2 == name { print $1 }' "$temporary_dir/checksums.txt")
	[ -n "$expected" ] || { echo "veil installer: checksum missing for $asset" >&2; exit 1; }
	if command -v sha256sum >/dev/null 2>&1; then
		actual=$(sha256sum "$temporary_dir/$asset" | awk '{print $1}')
	elif command -v shasum >/dev/null 2>&1; then
		actual=$(shasum -a 256 "$temporary_dir/$asset" | awk '{print $1}')
	else
		echo "veil installer: sha256sum or shasum is required" >&2
		exit 1
	fi
	[ "$actual" = "$expected" ] || { echo "veil installer: checksum verification failed for $asset" >&2; exit 1; }
}

verify_asset "$client_archive"
[ "$install_relay" -eq 0 ] || verify_asset "$relay_archive"

mkdir -p "$install_dir"
tar -xzf "$temporary_dir/$client_archive" -C "$temporary_dir" veil
install -m 0755 "$temporary_dir/veil" "$install_dir/veil"
if [ "$install_relay" -eq 1 ]; then
	tar -xzf "$temporary_dir/$relay_archive" -C "$temporary_dir" veil-relay
	install -m 0755 "$temporary_dir/veil-relay" "$install_dir/veil-relay"
fi

echo "veil ${requested_version} installed to $install_dir/veil"
if [ "$install_relay" -eq 1 ]; then
	echo "veil-relay ${requested_version} installed to $install_dir/veil-relay"
fi
case ":${PATH:-}:" in
	*":$install_dir:"*) ;;
	*) echo "Add $install_dir to PATH, then run: veil" ;;
esac
