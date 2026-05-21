#!/bin/sh
# SkillScan installer. Downloads the latest release binary for the current platform.
#
# Usage:
#   curl -fsSL https://armur-ai.github.io/skillscan/install.sh | sh
#   curl -fsSL https://armur-ai.github.io/skillscan/install.sh | PREFIX=$HOME/.local sh
#   curl -fsSL https://armur-ai.github.io/skillscan/install.sh | VERSION=v0.2.0 sh

set -eu

REPO="Armur-Ai/skillscan"
BIN="skillscan"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"

uname_s=$(uname -s 2>/dev/null || echo Unknown)
uname_m=$(uname -m 2>/dev/null || echo unknown)

case "$uname_s-$uname_m" in
  Darwin-arm64)  TARGET="aarch64-apple-darwin" ;;
  Darwin-x86_64) TARGET="x86_64-apple-darwin" ;;
  Linux-x86_64)  TARGET="x86_64-unknown-linux-musl" ;;
  Linux-aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
  *)
    echo "skillscan: unsupported platform $uname_s/$uname_m" >&2
    echo "Build from source with: cargo install --locked skillscan" >&2
    exit 1
    ;;
esac

if [ "${VERSION:-}" != "" ]; then
  TAG="$VERSION"
else
  TAG=$(
    curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
      | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' \
      | head -n 1
  )
  if [ -z "$TAG" ]; then
    echo "skillscan: could not resolve latest release tag." >&2
    exit 1
  fi
fi

ASSET="skillscan-$TAG-$TARGET.tar.gz"
URL="https://github.com/$REPO/releases/download/$TAG/$ASSET"

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t skillscan)
trap 'rm -rf "$TMP"' EXIT

echo "skillscan: downloading $URL"
if ! curl -fsSL "$URL" -o "$TMP/$ASSET"; then
  echo "skillscan: download failed." >&2
  exit 1
fi

tar -xzf "$TMP/$ASSET" -C "$TMP"
SRC="$TMP/skillscan-$TAG-$TARGET/$BIN"
if [ ! -x "$SRC" ]; then
  echo "skillscan: archive did not contain $BIN at expected path $SRC" >&2
  exit 1
fi

if [ -w "$BINDIR" ]; then
  install -m 755 "$SRC" "$BINDIR/$BIN"
elif command -v sudo >/dev/null 2>&1; then
  echo "skillscan: installing into $BINDIR (sudo)"
  sudo install -m 755 "$SRC" "$BINDIR/$BIN"
else
  mkdir -p "$HOME/.local/bin"
  install -m 755 "$SRC" "$HOME/.local/bin/$BIN"
  BINDIR="$HOME/.local/bin"
  echo "skillscan: $BINDIR is not on \$PATH; you may need to add it."
fi

echo "skillscan: installed $BIN $TAG to $BINDIR"
"$BINDIR/$BIN" --version
