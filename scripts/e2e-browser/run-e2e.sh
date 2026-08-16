#!/usr/bin/env bash
# 8S3C.1 browser E2E — canonical runner (tasks D/E).
#
# WHY THIS RUNNER: this host's system Chromium (both the cached playwright
# build AND the headless shell) crashes the renderer in the media/compositor
# path the moment the AUTHENTICATED LibreChat dashboard loads (renderer
# SIGTRAP, silent exit 0). Verified empirically 2026-08-16. The playwright
# docker image (mcr.microsoft.com/playwright:v1.56.1-noble) ships a working
# Chromium-1194 — the exact revision @playwright/test 1.56.1 wants — so the
# suite runs there, reaching the DEPLOYED LibreChat via --network host.
#
# Uses session-injection auth (no /api/auth/login) so the login rate-limiter
# ban is never tripped. Browser-test users live in the deployed Mongo; their
# credentials are in /tmp/e2e-user-creds.env (0600, NEVER committed).
#
# Usage:
#   scripts/e2e-browser/run-e2e.sh                 # full suite
#   scripts/e2e-browser/run-e2e.sh --grep J3       # subset
#   PW_IMAGE=mcr.microsoft.com/playwright:v1.56.1-noble scripts/e2e-browser/run-e2e.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKTREE="${REPO_ROOT}"            # /opt/cbhr-ai/LibreChat-wt-r3
HOST_APP_DIR="/opt/cbhr-ai/LibreChat"   # deployed app root holding .env (JWT secrets)
IMAGE="${PW_IMAGE:-mcr.microsoft.com/playwright:v1.56.1-noble}"
CHROME="${PW_CHROMIUM:-/ms-playwright/chromium-1194/chrome-linux/chrome}"

for p in "${WORKTREE}" "${HOST_APP_DIR}/.env"; do
  [ -e "$p" ] || { echo "missing $p" >&2; exit 1; }
done

docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"

echo ">> 8S3C.1 browser E2E via ${IMAGE}"
exec docker run --rm --network host \
  -v "${WORKTREE}:${WORKTREE}" \
  -v "${HOST_APP_DIR}:${HOST_APP_DIR}:ro" \
  -e PW_CHROMIUM="${CHROME}" \
  "${IMAGE}" \
  bash -c "cd '${WORKTREE}' && PW_CHROMIUM='${CHROME}' './node_modules/.bin/playwright' test $*"
