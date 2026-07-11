#!/usr/bin/env bash
set -euo pipefail
# One-shot local runner for the privsep e2e harness (mirrors the CI job).
# Uses sudo podman for reliable chroot/setuid; drop sudo if your podman is rootful.
cd "$(dirname "$0")/../.."
sudo podman build -t quish-privsep-e2e -f dist/test/Containerfile .
sudo podman run --rm quish-privsep-e2e
