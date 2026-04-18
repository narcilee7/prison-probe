#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 v0.1.0"
    exit 1
fi

echo "=== pp Release Script ==="
echo "Version: $VERSION"

# 1. Run tests
echo "[1/5] Running tests..."
cargo test --workspace --exclude pp-gui

# 2. Run cargo vet
echo "[2/5] Running cargo vet..."
cargo vet

# 3. Build release binaries
echo "[3/5] Building release binaries..."
cargo build --bin pp --release

# 4. Create git tag
echo "[4/5] Creating git tag $VERSION..."
git tag -a "$VERSION" -m "Release $VERSION"

echo "[5/5] Push tag to trigger GitHub Actions release..."
git push origin "$VERSION"

echo ""
echo "Release tag pushed! GitHub Actions will build and publish binaries."
echo "After release is published, update Homebrew Formula SHA-256s:"
echo "  shasum -a 256 target/release/pp"
