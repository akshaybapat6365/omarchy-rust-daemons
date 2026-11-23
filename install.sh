#!/usr/bin/env bash
# install.sh — Build and install vitalsd, screenshotd, and everythingd (Omarchy Rust daemons).
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="$HOME/.local/bin"
NATIVE_CPU=0
JOBS=""
SKIP_SMOKE=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [OPTIONS]

Build the omarchy-rust-daemons workspace in release mode and install
vitalsd, screenshotd, and everythingd.

Options:
  --prefix DIR    Binary install directory (default: ~/.local/bin)
  --native        Compile with RUSTFLAGS="-C target-cpu=native" for host AVX2/NEON tuning
  --jobs N        Override parallel cargo jobs
  --skip-smoke    Skip post-install binary smoke checks
  -h, --help      Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)     PREFIX="$2"; shift 2 ;;
    --native)     NATIVE_CPU=1; shift ;;
    --jobs)       JOBS="$2"; shift 2 ;;
    --skip-smoke) SKIP_SMOKE=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *)            echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v cargo >/dev/null 2>&1 || { echo "error: cargo not found in PATH" >&2; exit 1; }

BUILD_ARGS=(build --release --workspace --locked)
[[ -n "$JOBS" ]] && BUILD_ARGS+=(--jobs "$JOBS")

echo "==> Building workspace (vitalsd, screenshotd, everythingd)"
(
  cd "$SCRIPT_DIR"
  if (( NATIVE_CPU == 1 )); then
    echo "    Mode: host-tuned (-C target-cpu=native)"
    RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=native" nice -n 19 cargo "${BUILD_ARGS[@]}"
  else
    echo "    Mode: portable release"
    nice -n 19 cargo "${BUILD_ARGS[@]}"
  fi
)

TARGET_DIR="${CARGO_TARGET_DIR:-$SCRIPT_DIR/target}"
mkdir -p "$PREFIX"

echo "==> Installing binaries into $PREFIX"
for bin in vitalsd screenshotd everythingd; do
  install -m 0755 "$TARGET_DIR/release/$bin" "$PREFIX/$bin"
  echo "    [installed] $PREFIX/$bin ($(du -h "$PREFIX/$bin" | awk '{print $1}'))"
done

if (( SKIP_SMOKE == 0 )); then
  echo "==> Running post-install smoke checks"
  vitals_out="$("$PREFIX/vitalsd" --once | head -c 160 | tr '\n' ' ' || true)"
  if [[ "$vitals_out" == *'"cpu":'* ]]; then
    echo "    [ok] vitalsd --once emitted valid telemetry JSON"
  else
    echo "error: vitalsd --once smoke check failed" >&2; exit 1
  fi
  shot_out="$("$PREFIX/screenshotd" 2>&1 || true)"
  if [[ "$shot_out" == *"usage: screenshotd"* ]]; then
    echo "    [ok] screenshotd CLI contract verified"
  else
    echo "error: screenshotd usage smoke check failed" >&2; exit 1
  fi
  ev_out="$("$PREFIX/everythingd" 2>&1 || true)"
  if [[ "$ev_out" == *"Everything helper"* ]]; then
    echo "    [ok] everythingd CLI contract verified"
  else
    echo "error: everythingd usage smoke check failed" >&2; exit 1
  fi
fi

echo
echo "Install complete! Ensure $PREFIX is in your PATH."
