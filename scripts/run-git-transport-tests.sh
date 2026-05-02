#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Run Git's transport test suite with gitway as the SSH transport (NFR-8, S4).
#
# Prerequisites:
#   - gitway binary in PATH (or GITWAY_BIN set to full path)
#   - git source tree at GIT_SRC (defaults to a fresh clone)
#   - SSH credentials accessible (agent or identity file)
#
# Usage:
#   ./scripts/run-git-transport-tests.sh
#   GITWAY_BIN=./target/release/gitway GIT_SRC=/tmp/git ./scripts/run-git-transport-tests.sh
#
# Tests run:
#   t5500-fetch-pack.sh  — fetch-pack / upload-pack protocol
#   t5516-fetch-pack-v2.sh — protocol v2
#
# Exit code mirrors the test suite: 0 = all passed, non-zero = failure.

set -euo pipefail

GITWAY_BIN="${GITWAY_BIN:-$(command -v gitway || echo "./target/release/gitway")}"
GIT_SRC="${GIT_SRC:-/tmp/git-src}"
GIT_TEST_DIR="${GIT_SRC}/t"

# ── Resolve gitway binary ────────────────────────────────────────────────────

if [[ ! -x "${GITWAY_BIN}" ]]; then
    echo "ERROR: gitway binary not found at '${GITWAY_BIN}'" >&2
    echo "       Run: cargo build --release && export GITWAY_BIN=./target/release/gitway" >&2
    exit 1
fi

echo "Using gitway: ${GITWAY_BIN}"
"${GITWAY_BIN}" --test 2>/dev/null || true  # prints version, ignore auth failure

# ── Clone git source if needed ───────────────────────────────────────────────

if [[ ! -d "${GIT_SRC}/.git" ]]; then
    echo "Cloning git source to ${GIT_SRC}..."
    git clone --depth=1 "https://github.com/git/git.git" "${GIT_SRC}"
fi

# ── Build git from source ────────────────────────────────────────────────────

echo "Building git from source..."
make -C "${GIT_SRC}" -j"$(nproc)" 2>&1 | tail -5

# ── Run the transport tests ──────────────────────────────────────────────────

export GIT_SSH_COMMAND="${GITWAY_BIN}"
export GIT_TEST_DEFAULT_INITIAL_BRANCH_NAME=main

echo "Running t5500-fetch-pack.sh..."
(cd "${GIT_TEST_DIR}" && prove -v ./t5500-fetch-pack.sh)

echo "Running t5516-fetch-pack-v2.sh..."
(cd "${GIT_TEST_DIR}" && prove -v ./t5516-fetch-pack-v2.sh)

echo "All transport tests passed."
