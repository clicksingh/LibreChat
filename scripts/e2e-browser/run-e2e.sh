#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKTREE="${REPO_ROOT}"
HOST_APP_DIR="/opt/cbhr-ai/LibreChat"
IMAGE="${PW_IMAGE:-mcr.microsoft.com/playwright:v1.56.1-noble}"
CHROME="${PW_CHROMIUM:-/ms-playwright/chromium-1194/chrome-linux/chrome}"

for p in "${WORKTREE}" "${HOST_APP_DIR}/.env"; do
  [ -e "$p" ] || { echo "missing $p" >&2; exit 1; }
done

docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"

MOUNTS=(-v "${WORKTREE}:${WORKTREE}")
if [ "${HOST_APP_DIR}" != "${WORKTREE}" ]; then
  MOUNTS+=(-v "${HOST_APP_DIR}:${HOST_APP_DIR}:ro")
fi

echo ">> CBHR browser E2E via ${IMAGE}"

exec docker run --rm --network host \
  "${MOUNTS[@]}" \
  -e PW_CHROMIUM="${CHROME}" \
  "${IMAGE}" \
  bash -c "cd '${WORKTREE}' && if [ -x './node_modules/.bin/playwright' ]; then PW_CHROMIUM='${CHROME}' ./node_modules/.bin/playwright test $*; else PW_CHROMIUM='${CHROME}' node node_modules/playwright/cli.js test $*; fi"
