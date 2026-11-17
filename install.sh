#!/usr/bin/env bash
# ax installer: fetches the latest source and builds it with cargo.
#   curl -fsSL https://raw.githubusercontent.com/pacman-Sy/ax/main/install.sh | bash
# Environment:
#   AX_PREFIX   install directory (default: $HOME/.local/bin)
#   AX_REF      git ref to build (default: main)
set -euo pipefail

PREFIX="${AX_PREFIX:-$HOME/.local/bin}"
REF="${AX_REF:-main}"
REPO="https://github.com/pacman-Sy/ax"

say() { printf 'ax: %s\n' "$*" >&2; }
die() { printf 'ax: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"; }

need tar
need git

if ! command -v cargo >/dev/null 2>&1; then
    if [ -x "$HOME/.cargo/bin/cargo" ]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    else
        say "cargo not found — install Rust first: https://rustup.rs"
        die "missing toolchain"
    fi
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

say "fetching $REPO ($REF)"
git clone --depth 1 --branch "$REF" "$REPO" "$work/ax" >/dev/null 2>&1 \
    || die "could not clone $REPO at ref $REF"

say "building (this takes about a minute)"
( cd "$work/ax" && cargo build --release --quiet ) || die "build failed"

mkdir -p "$PREFIX"
install -m 0755 "$work/ax/target/release/ax" "$PREFIX/ax"

say "installed $PREFIX/ax"
case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *) say "add it to PATH: export PATH=\"$PREFIX:\$PATH\"" ;;
esac

"$PREFIX/ax" version
