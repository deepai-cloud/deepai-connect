#!/bin/sh
# Install the CLI for the current user. This does not join or modify a cluster.
set -eu

fail() { printf 'deepai-connect installer: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Usage: sh install.sh [--from-source | --from-dir DIR] [--version VERSION]
                     [--bin-dir DIR] [--no-path]
       sh install.sh --rollback|--uninstall [--bin-dir DIR]

Default: install the bundle beside this script, or download a published release.
--from-source  Build this checkout with Go; no published release is required.
--from-dir    Install a local release artifact verified against its SHA256SUMS.
--bin-dir     Install directory (default: $HOME/.local/bin).
--no-path     Do not append PATH configuration to shell startup files.
--rollback    Restore the previous CLI binary; never restart services.
--uninstall   Remove only the managed CLI and backup; retain config/identity/PATH.

Installing the CLI never enables automatic startup or joins a device.
Uninstall refuses binaries referenced by Connect service/startup registrations.
EOF
}

[ -n "${HOME:-}" ] || fail 'HOME is not set'
bin_dir="$HOME/.local/bin"
source_mode=download
from_dir=
version=
setup_path=yes
action=install
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
        --rollback|--uninstall)
            [ "$action" = install ] || fail 'choose only one action'
            action=${1#--}; shift ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
done

[ "$action" = install ] || { [ "$source_mode" = download ] && [ -z "$version" ] || fail 'rollback/uninstall do not accept an installation source or version'; }

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
if [ "$source_mode" = download ] && [ -z "$version" ]; then
    bundle_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
    if [ -f "$bundle_dir/SHA256SUMS" ]; then
        source_mode=directory
        from_dir=$bundle_dir
    fi
fi
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
digest() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
    else fail 'sha256sum or shasum is required'; fi
}
receipt="$bin_dir/.deepai-connect.sha256"
previous="$bin_dir/.deepai-connect.previous"
previous_receipt="$bin_dir/.deepai-connect.previous.sha256"
transaction="$bin_dir/.deepai-connect.transaction"
for item in "$receipt" "$previous" "$previous_receipt" "$transaction"; do
    no_links "$item"
    [ ! -e "$item" ] || [ -f "$item" ] || fail "refusing non-file: $item"
done
check_managed() {
    [ -f "$1" ] && [ -f "$2" ] || fail 'no managed CLI or backup found; install a verified bundle first'
    [ "$(digest "$1")" = "$(cat "$2")" ] || fail 'managed CLI or backup was changed; refusing to remove or replace it'
}
# A tiny transaction record makes interruption between executable and receipt
# renames recoverable. It contains hashes only, never device state or credentials.
valid_digest() {
    [ "$1" = - ] && return 0
    [ "${#1}" = 64 ] || return 1
    case "$1" in *[!a-f0-9]*) return 1 ;; esac
}
recover_transaction() {
    [ -e "$transaction" ] || return 0
    tx_old= tx_new= tx_backup= tx_extra=
    IFS=' ' read -r tx_old tx_new tx_backup tx_extra < "$transaction" || fail 'invalid installer transaction'
    valid_digest "$tx_old" && valid_digest "$tx_new" && valid_digest "$tx_backup" && [ "$tx_new" != - ] && [ -z "$tx_extra" ] || fail 'invalid installer transaction'
    tx_current=-
    [ ! -e "$bin_dir/deepai-connect" ] || tx_current=$(digest "$bin_dir/deepai-connect")
    [ "$tx_current" = "$tx_old" ] || [ "$tx_current" = "$tx_new" ] || fail 'interrupted installation binary changed; preserve transaction and inspect manually'
    tx_previous=-
    [ ! -e "$previous" ] || tx_previous=$(digest "$previous")
    [ "$tx_previous" = "$tx_old" ] || [ "$tx_previous" = "$tx_backup" ] || fail 'interrupted installation backup changed; preserve transaction and inspect manually'
    if [ "$tx_current" = "$tx_new" ] && [ "$tx_old" != - ] && [ "$tx_old" != "$tx_new" ] && [ "$tx_previous" != "$tx_old" ]; then fail 'interrupted installation lost its rollback binary; preserve transaction and inspect manually'; fi
    if [ "$tx_current" != - ]; then printf '%s\n' "$tx_current" > "$receipt"; fi
    if [ "$tx_previous" != - ]; then printf '%s\n' "$tx_previous" > "$previous_receipt"; fi
    rm -f "$transaction"
}
check_service_references() {
    # Files are inspected only; never load/unload services or touch Gateway Node.
    for unit in /etc/systemd/system/deepai-connect*.service \
        /run/systemd/system/deepai-connect*.service \
        /usr/lib/systemd/system/deepai-connect*.service \
        /lib/systemd/system/deepai-connect*.service \
        /etc/systemd/system/deepai-connect*.service.d/*.conf \
        /run/systemd/system/deepai-connect*.service.d/*.conf \
        "$HOME"/.config/systemd/user/deepai-connect*.service \
        "$HOME"/Library/LaunchAgents/cloud.deepai.connect*.plist \
        /Library/LaunchDaemons/cloud.deepai.connect*.plist; do
        [ -e "$unit" ] || continue
        [ -r "$unit" ] || fail "cannot inspect startup registration: $unit"
        case "$unit" in *cloud.deepai.connect.vm.*.plist) fail "Connect login registration exists: $unit; run vm startup disable before uninstalling" ;; esac
        if grep -Fq "$bin_dir/deepai-connect" "$unit"; then
            fail "CLI is referenced by $unit; remove that Connect registration before uninstalling"
        fi
    done
}
check_destination
recover_transaction
if [ "$action" = uninstall ]; then
    check_service_references
    if [ ! -e "$bin_dir/deepai-connect" ] && [ ! -e "$receipt" ] && [ ! -e "$previous" ] && [ ! -e "$previous_receipt" ]; then
        printf 'CLI is already uninstalled. Configuration, identities and startup preferences retained.\n'
        exit 0
    fi
    check_managed "$bin_dir/deepai-connect" "$receipt"
    if [ -e "$previous" ] || [ -e "$previous_receipt" ]; then check_managed "$previous" "$previous_receipt"; fi
    rm -f "$bin_dir/deepai-connect" "$receipt" "$previous" "$previous_receipt"
    printf 'Removed managed CLI. Configuration, identities and shell PATH entries retained.\n'
    exit 0
fi
if [ -e "$previous" ] || [ -e "$previous_receipt" ]; then check_managed "$previous" "$previous_receipt"; fi
if [ "$action" = rollback ]; then
    check_managed "$bin_dir/deepai-connect" "$receipt"
    check_managed "$previous" "$previous_receipt"
fi
mkdir -p "$bin_dir"
stage=$(mktemp -d "$bin_dir/.deepai-connect-install.XXXXXX")
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM

if [ "$action" = rollback ]; then
    cp "$previous" "$stage/$asset"
elif [ "$source_mode" = source ]; then
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
    actual=$(digest "$stage/$asset")
    [ "$actual" = "$expected" ] || fail "checksum mismatch for $asset; previous installation is unchanged"
fi

chmod 0755 "$stage/$asset"
check_destination
# Commit hashes first so a later invocation can repair receipts after a crash.
old_digest=-
backup_digest=-
[ ! -e "$bin_dir/deepai-connect" ] || old_digest=$(digest "$bin_dir/deepai-connect")
[ ! -e "$previous" ] || backup_digest=$(digest "$previous")
printf '%s %s %s\n' "$old_digest" "$(digest "$stage/$asset")" "$backup_digest" > "$stage/transaction"
chmod 0600 "$stage/transaction"
mv -f "$stage/transaction" "$transaction"
# Reinstalling identical bytes keeps the useful rollback version.
if [ -e "$bin_dir/deepai-connect" ] && ! cmp -s "$stage/$asset" "$bin_dir/deepai-connect"; then
    cp -p "$bin_dir/deepai-connect" "$stage/previous"
    digest "$stage/previous" > "$stage/previous.sha256"
    mv -f "$stage/previous" "$previous"
    mv -f "$stage/previous.sha256" "$previous_receipt"
fi
digest "$stage/$asset" > "$stage/receipt"
mv -f "$stage/$asset" "$bin_dir/deepai-connect"
mv -f "$stage/receipt" "$receipt"
rm -f "$transaction"
printf 'Installed %s\n' "$bin_dir/deepai-connect"
printf 'CLI only: no service, login item, VM, mesh or startup preference was changed.\n'
if [ "$action" = rollback ]; then exit 0; fi

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
printf 'Next: deepai-connect setup --hub USER@HOST\n'
printf 'Then: deepai-connect status\n'
