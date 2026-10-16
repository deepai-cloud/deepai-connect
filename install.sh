#!/bin/sh
# Install the CLI for the current user. This does not join or modify a cluster.
set -eu

fail() { printf 'deepai-connect installer: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Usage: sh install.sh [--from-source | --from-dir DIR] [--version VERSION]
                     [--bin-dir DIR] [--no-path]

Default: download a published GitHub release (latest unless --version is set).
--from-source  Build this checkout with Go; no published release is required.
--from-dir    Install a local release artifact verified against its SHA256SUMS.
--bin-dir     Install directory (default: $HOME/.local/bin).
--no-path     Do not append PATH configuration to shell startup files.
EOF
}

[ -n "${HOME:-}" ] || fail 'HOME is not set'
bin_dir="$HOME/.local/bin"
source_mode=download
from_dir=
version=
setup_path=yes
while [ "$#" -gt 0 ]; do
    case "$1" in
        --from-source)
            [ "$source_mode" = download ] || fail 'choose only one installation source'
            source_mode=source; shift ;;
        --from-dir|--version|--bin-dir)
            [ "$#" -ge 2 ] && [ -n "$2" ] || fail "$1 requires a value"
            case "$1" in
                --from-dir)
                    [ "$source_mode" = download ] || fail 'choose only one installation source'
                    source_mode=directory; from_dir=$2 ;;
                --version) version=$2 ;;
                --bin-dir) bin_dir=$2 ;;
            esac
            shift 2 ;;
        --no-path) setup_path=no; shift ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
done

case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) fail 'supported systems are Linux and macOS' ;;
esac
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) fail 'supported architectures are amd64 and arm64' ;;
esac
asset="deepai-connect-$os-$arch"
if [ -n "$version" ]; then
    case "$version" in
        [!a-zA-Z0-9]*|*[!a-zA-Z0-9._+-]*) fail 'invalid version' ;;
    esac
    [ "${#version}" -le 64 ] || fail 'version is too long'
fi

# PATH cannot represent colons or newlines in directory names. Reject ambiguous
# components instead of resolving symlinks into an unexpected installation.
case "$bin_dir" in
    /*) ;;
    *) bin_dir="$PWD/$bin_dir" ;;
esac
case "$bin_dir" in
    *:*) fail 'installation directory cannot contain a colon' ;;
    *'
'*) fail 'installation directory cannot contain a newline' ;;
esac
while [ "${bin_dir%/}" != "$bin_dir" ]; do bin_dir=${bin_dir%/}; done
[ -n "$bin_dir" ] || fail 'refusing installation in the filesystem root'
case "/$bin_dir/" in
    */../*|*/./*) fail 'installation directory cannot contain . or .. components' ;;
esac
no_links() {
    check_path=$1
    while [ "$check_path" != / ] && [ -n "$check_path" ]; do
        [ ! -L "$check_path" ] || fail "refusing symlink: $check_path"
        check_path=$(dirname "$check_path")
    done
}
check_destination() {
    no_links "$bin_dir/deepai-connect"
    if [ -e "$bin_dir/deepai-connect" ]; then
        [ -f "$bin_dir/deepai-connect" ] && [ -x "$bin_dir/deepai-connect" ] && [ -w "$bin_dir/deepai-connect" ] ||
            fail "refusing to replace a non-executable or unwritable file: $bin_dir/deepai-connect"
    fi
}
check_destination
mkdir -p "$bin_dir"
stage=$(mktemp -d "$bin_dir/.deepai-connect-install.XXXXXX")
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM

if [ "$source_mode" = source ]; then
    command -v go >/dev/null 2>&1 || fail '--from-source requires Go; install Go or use a published release'
    repo=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
    [ -f "$repo/go.mod" ] && [ -d "$repo/cmd/deepai-connect" ] || fail '--from-source must run from a project checkout'
    version=${version:-dev}
    printf 'Building deepai-connect for %s/%s...\n' "$os" "$arch"
    (cd "$repo" && GOTOOLCHAIN=auto GOWORK=off CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
        GOAMD64=v1 GOARM64=v8.0 GOFLAGS= GOEXPERIMENT= \
        go build -trimpath -buildvcs=false \
        -ldflags "-s -w -X github.com/deepai-cloud/deepai-connect/internal/buildinfo.Version=$version" \
        -o "$stage/$asset" ./cmd/deepai-connect) || fail 'source build failed; previous installation is unchanged'
else
    if [ "$source_mode" = directory ]; then
        [ -f "$from_dir/$asset" ] || fail "missing local artifact: $from_dir/$asset"
        [ -f "$from_dir/SHA256SUMS" ] || fail "missing checksum file: $from_dir/SHA256SUMS"
        cp "$from_dir/$asset" "$stage/$asset"
        cp "$from_dir/SHA256SUMS" "$stage/SHA256SUMS"
    else
        command -v curl >/dev/null 2>&1 || fail 'curl is required to download releases'
        version=${version:-latest}
        base=https://github.com/deepai-cloud/deepai-connect/releases
        if [ "$version" = latest ]; then base="$base/latest/download"; else base="$base/download/$version"; fi
        for name in SHA256SUMS "$asset"; do
            curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error \
                --location --output "$stage/$name" "$base/$name" ||
                fail "could not download $name for release $version; that release may not publish $os/$arch. Use --from-source in a checkout or --from-dir with a local release."
        done
    fi
    expected=$(awk -v name="$asset" '$2 == name { count++; digest = $1 } END { if (count != 1 || length(digest) != 64 || digest ~ /[^a-fA-F0-9]/) exit 1; print tolower(digest) }' "$stage/SHA256SUMS") ||
        fail "SHA256SUMS must contain exactly one valid checksum for $asset"
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$stage/$asset" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$stage/$asset" | awk '{print $1}')
    else
        fail 'sha256sum or shasum is required to verify the download'
    fi
    [ "$actual" = "$expected" ] || fail "checksum mismatch for $asset; previous installation is unchanged"
fi

chmod 0755 "$stage/$asset"
check_destination
mv -f "$stage/$asset" "$bin_dir/deepai-connect"
printf 'Installed %s\n' "$bin_dir/deepai-connect"

# Append only a small guarded block. Never source or rewrite an existing file.
shell_quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
quoted_bin=$(shell_quote "$bin_dir")
add_path() {
    profile=$1
    if [ -L "$profile" ] || { [ -e "$profile" ] && [ ! -f "$profile" ]; }; then
        printf 'Skipped unsafe startup file: %s\n' "$profile" >&2
        return
    fi
    marker="# deepai-connect PATH: $bin_dir"
    if [ -f "$profile" ] && grep -Fqx "$marker" "$profile"; then return; fi
    if ! { printf '\n%s\n' "$marker"; printf 'case ":$PATH:" in\n    *:%s:*) ;;\n    *) export PATH=%s:"$PATH" ;;\nesac\n' "$quoted_bin" "$quoted_bin"; } >> "$profile"; then
        printf 'Could not update startup file: %s\n' "$profile" >&2
        return
    fi
    printf 'Added terminal PATH to %s\n' "$profile"
}
if [ "$setup_path" = yes ]; then
    login_shell=${SHELL:-sh}
    case "${login_shell##*/}" in
        zsh)
            profile_dir=${ZDOTDIR:-$HOME}
            if [ -d "$profile_dir" ] && [ ! -L "$profile_dir" ]; then
                add_path "$profile_dir/.zshrc"
                add_path "$profile_dir/.zprofile"
            else
                printf 'Skipped missing or symlinked zsh startup directory: %s\n' "$profile_dir" >&2
            fi ;;
        bash)
            add_path "$HOME/.bashrc"
            if [ -e "$HOME/.bash_profile" ]; then add_path "$HOME/.bash_profile"
            elif [ -e "$HOME/.bash_login" ]; then add_path "$HOME/.bash_login"
            else add_path "$HOME/.profile"; fi ;;
        *) add_path "$HOME/.profile" ;;
    esac
    case ":${PATH:-}:" in
        *:"$bin_dir":*) ;;
        *) printf 'Open a new terminal, or run: export PATH=%s:"$PATH"\n' "$quoted_bin" ;;
    esac
fi
printf 'Run: deepai-connect --help\n'
