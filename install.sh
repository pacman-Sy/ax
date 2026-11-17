#!/usr/bin/env bash
# ax installer. Downloads a prebuilt static binary; falls back to building from
# source when there is no build for this platform.
#   curl -fsSL https://raw.githubusercontent.com/pacman-Sy/ax/main/install.sh | bash
# Environment:
#   AX_PREFIX   install directory (default: $HOME/.local/bin)
#   AX_REF      git ref to build from in the fallback path (default: main)
#   AX_SOURCE   set to 1 to skip the binary and build from source
set -euo pipefail

# Root installing system-wide lands in /usr/local/bin, which is already on
# PATH; everyone else gets ~/.local/bin and a PATH line in their shell rc.
if [ -n "${AX_PREFIX:-}" ]; then
    PREFIX="$AX_PREFIX"
elif [ "$(id -u 2>/dev/null || echo 1)" = "0" ] && [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    PREFIX=/usr/local/bin
else
    PREFIX="$HOME/.local/bin"
fi
REF="${AX_REF:-main}"
REPO="https://github.com/pacman-Sy/ax"
BASE="https://github.com/pacman-Sy/ax/releases/latest/download"

say() { printf 'ax: %s\n' "$*" >&2; }
die() { printf 'ax: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

get() {
    if have curl; then curl -fsSL "$1"; else wget -qO- "$1"; fi
}

download() {
    if have curl; then curl -fsSL -o "$2" "$1"; else wget -qO "$2" "$1"; fi
}

# ---- platform -------------------------------------------------------------

os="$(uname -s 2>/dev/null || echo unknown)"
arch="$(uname -m 2>/dev/null || echo unknown)"

case "$arch" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    armv7l|armv7) arch=armv7 ;;
    *) arch="$(printf '%s' "$arch")" ;;
esac

case "$os" in
    Linux)  os=linux ;;
    Darwin) os=macos ;;
    FreeBSD) os=freebsd ;;
    MINGW*|MSYS*|CYGWIN*) os=windows ;;
    *) os="$(printf '%s' "$os" | tr '[:upper:]' '[:lower:]')" ;;
esac

asset="ax-$os-$arch"
[ "$os" = windows ] && asset="$asset.exe"

# ---- prebuilt -------------------------------------------------------------

install_binary() {
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    say "downloading $asset"
    if ! download "$BASE/$asset" "$tmp/ax"; then
        rm -rf "$tmp"
        return 1
    fi

    if download "$BASE/$asset.sha256" "$tmp/sum" 2>/dev/null; then
        want="$(cut -d' ' -f1 < "$tmp/sum")"
        if have sha256sum; then
            got="$(sha256sum "$tmp/ax" | cut -d' ' -f1)"
        elif have shasum; then
            got="$(shasum -a 256 "$tmp/ax" | cut -d' ' -f1)"
        else
            got="$want"
        fi
        [ "$want" = "$got" ] || { say "checksum mismatch, discarding download"; rm -rf "$tmp"; return 1; }
    fi

    mkdir -p "$PREFIX"
    if have install; then
        install -m 0755 "$tmp/ax" "$PREFIX/ax"
    else
        cp "$tmp/ax" "$PREFIX/ax"
        chmod 0755 "$PREFIX/ax"
    fi
    rm -rf "$tmp"
    trap - EXIT
    return 0
}

# ---- source fallback ------------------------------------------------------

find_cargo() {
    if have cargo; then
        command -v cargo
        return 0
    fi
    for candidate in \
        "${CARGO_HOME:-}/bin/cargo" \
        "$HOME/.cargo/bin/cargo" \
        "/usr/local/cargo/bin/cargo" \
        "/usr/local/bin/cargo" \
        "/opt/rust/bin/cargo" \
        "/root/.cargo/bin/cargo"
    do
        if [ -n "$candidate" ] && [ -x "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

install_rust() {
    say "no cargo found — installing a minimal Rust toolchain"
    if have rustup; then
        rustup toolchain install stable --profile minimal >&2
        return 0
    fi
    have curl || die "need curl to install Rust (or install it from https://rustup.rs)"

    tmp_init="$(mktemp)"
    curl -fsSL https://sh.rustup.rs -o "$tmp_init" || die "could not download rustup"
    if ! sh "$tmp_init" -y --profile minimal --no-modify-path --default-toolchain stable; then
        rm -f "$tmp_init"
        die "rustup install failed"
    fi
    rm -f "$tmp_init"
}

install_source() {
    say "no prebuilt binary for $os-$arch, building from source"
    have git || die "git is required to build from source"

    if ! CARGO="$(find_cargo)"; then
        install_rust
        CARGO="$(find_cargo)" || die "could not locate cargo after installing Rust"
    fi
    export PATH="$(dirname "$CARGO"):$PATH"
    say "using $("$CARGO" --version)"

    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT

    say "fetching $REPO ($REF)"
    git clone --depth 1 --branch "$REF" "$REPO" "$work/ax" >/dev/null 2>&1 \
        || die "could not clone $REPO at ref $REF"

    say "building (this takes about a minute)"
    ( cd "$work/ax" && "$CARGO" build --release --quiet ) || die "build failed"

    mkdir -p "$PREFIX"
    if have install; then
        install -m 0755 "$work/ax/target/release/ax" "$PREFIX/ax"
    else
        cp "$work/ax/target/release/ax" "$PREFIX/ax"
        chmod 0755 "$PREFIX/ax"
    fi
    rm -rf "$work"
    trap - EXIT
}

# ---- go ------------------------------------------------------------------

if [ "${AX_SOURCE:-0}" = "1" ] || ! install_binary; then
    install_source
fi

say "installed $PREFIX/ax"

# Make it callable in the next shell instead of leaving the user to edit PATH.
on_path=0
case ":$PATH:" in
    *":$PREFIX:"*) on_path=1 ;;
esac

if [ "$on_path" = "0" ]; then
    line="export PATH=\"$PREFIX:\$PATH\""
    stamped="# added by the ax installer"
    for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if [ -f "$rc" ] && grep -qF "$line" "$rc" 2>/dev/null; then
            on_path=2
            break
        fi
    done
    if [ "$on_path" = "0" ]; then
        rc="$HOME/.bashrc"
        [ -n "${ZSH_VERSION:-}" ] && rc="$HOME/.zshrc"
        if [ -w "$rc" ] || [ -w "$(dirname "$rc")" ]; then
            printf '\n%s\n%s\n' "$stamped" "$line" >> "$rc"
            say "added $PREFIX to PATH in $rc — run: . $rc"
        else
            say "add it to PATH: $line"
        fi
    fi
fi

"$PREFIX/ax" version
