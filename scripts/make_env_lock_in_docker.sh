#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   bash scripts/make_env_lock_in_docker.sh <SNAPSHOT_DIR> <ENV_DIR>
#
# Example:
#   bash scripts/make_env_lock_in_docker.sh \
#     snapshots/PYSEC-2025-26/R_fix \
#     environments/snowflakedb__snowflake-connector-python-py310
#
# This script:
#   1. Reads PYTHON_IMAGE from <ENV_DIR>/env.conf
#   2. Reads apt packages from <ENV_DIR>/apt-packages.txt
#   3. Starts a temporary Docker container with docker run --rm
#   4. Installs system deps + Python deps
#   5. Generates <ENV_DIR>/requirements-lock.txt
#
# Important:
#   - Core install `pip install -e .` failure is fatal.
#   - Optional extras failure is non-fatal.
#   - The current project itself is excluded from requirements-lock.txt.

if [ $# -ne 2 ]; then
    echo "Usage: $(basename "$0") <SNAPSHOT_DIR> <ENV_DIR>" >&2
    exit 2
fi

SNAPSHOT_DIR="$1"
ENV_DIR="$2"

ABS_SNAPSHOT="$(realpath "$SNAPSHOT_DIR")"
ABS_ENV="$(realpath "$ENV_DIR")"

ENV_CONF="$ABS_ENV/env.conf"
APT_FILE="$ABS_ENV/apt-packages.txt"
LOCK_FILE="$ABS_ENV/requirements-lock.txt"

if [ ! -d "$ABS_SNAPSHOT" ]; then
    echo "[ERROR] snapshot directory not found: $ABS_SNAPSHOT" >&2
    exit 1
fi

if [ ! -d "$ABS_ENV" ]; then
    echo "[ERROR] environment directory not found: $ABS_ENV" >&2
    exit 1
fi

if [ ! -f "$ENV_CONF" ]; then
    echo "[ERROR] env.conf not found: $ENV_CONF" >&2
    exit 1
fi

# Read PYTHON_IMAGE from env.conf.
# Expected format:
#   PYTHON_IMAGE=python:3.10-slim-bookworm
# shellcheck source=/dev/null
source "$ENV_CONF"

PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.10-slim-bookworm}"

echo "[INFO] PYTHON_IMAGE = $PYTHON_IMAGE"
echo "[INFO] SNAPSHOT     = $ABS_SNAPSHOT"
echo "[INFO] ENV_DIR      = $ABS_ENV"
echo "[INFO] LOCK_FILE    = $LOCK_FILE"

docker run --rm \
    -v "$ABS_SNAPSHOT:/src:ro" \
    -v "$ABS_ENV:/env:rw" \
    -w /work \
    "$PYTHON_IMAGE" \
    bash -lc '
        set -euo pipefail

        echo "[INFO] base image python:"
        python --version

        # ---------------------------------------------------------------------
        # 1. Install apt packages
        # ---------------------------------------------------------------------
        APT_FILE="/env/apt-packages.txt"

        if [ -f "$APT_FILE" ]; then
            echo "[INFO] reading apt packages from $APT_FILE"

            # Remove comments and blank lines.
            sed -E "s/#.*$//" "$APT_FILE" | awk "NF {print}" > /tmp/apt-packages.clean

            if [ -s /tmp/apt-packages.clean ]; then
                echo "[INFO] installing apt packages..."
                apt-get update
                xargs -r apt-get install -y --no-install-recommends < /tmp/apt-packages.clean
                rm -rf /var/lib/apt/lists/*
            else
                echo "[WARN] apt-packages.txt has no active packages; skipping apt install"
            fi
        else
            echo "[WARN] apt-packages.txt not found; skipping apt install"
        fi

        # ---------------------------------------------------------------------
        # 2. Create temporary venv
        # ---------------------------------------------------------------------
        echo "[INFO] creating temporary venv..."
        python -m venv /tmp/lockenv
        source /tmp/lockenv/bin/activate

        echo "[INFO] venv python:"
        python --version

        echo "[INFO] installing pinned build tools..."
        python -m pip install --upgrade \
            pip==24.0 \
            setuptools==69.5.1 \
            wheel==0.43.0

        # ---------------------------------------------------------------------
        # 3. Copy source snapshot into writable location
        # ---------------------------------------------------------------------
        echo "[INFO] copying snapshot to /work/repo..."
        cp -a /src /work/repo
        cd /work/repo

        # ---------------------------------------------------------------------
        # 4. Install project dependencies
        # ---------------------------------------------------------------------
        echo "[INFO] installing project with: python -m pip install -e ."
        python -m pip install -e .

        # ---------------------------------------------------------------------
        # 5. Try optional extras
        # ---------------------------------------------------------------------
        # These extras may not exist. Failure is allowed.
        for extra in test tests dev testing all pandas; do
            echo "[TRY] optional extra: $extra"

            if python -m pip install -e ".[$extra]"; then
                echo "[OK] optional extra installed or accepted: $extra"
            else
                echo "[WARN] optional extra failed or not found: $extra"
            fi
        done

        # ---------------------------------------------------------------------
        # 6. Install common benchmark test tools
        # ---------------------------------------------------------------------
        echo "[INFO] installing common benchmark test tools..."
        python -m pip install \
            pytest \
            pytest-asyncio \
            pytest-mock \
            hypothesis \
            requests \
            responses \
            freezegun \
            packaging \
            attrs \
            mock \
            parameterized

        # ---------------------------------------------------------------------
        # 7. Freeze dependencies
        # ---------------------------------------------------------------------
        echo "[INFO] freezing dependencies..."

        # Exclude the editable project itself.
        # We want requirements-lock.txt to contain dependencies only,
        # because validation later installs each snapshot with:
        #   python -m pip install --no-deps --no-build-isolation -e .
        python -m pip freeze --exclude-editable \
            | awk '\''!/\/work\/repo/ && !/file:\/\/\/work\/repo/ && !/^-e[[:space:]]/'\'' \
            | sort > /env/requirements-lock.txt

        # Safety check: lock file should not contain local project paths.
        if grep -E "(/work/repo|file:///work/repo|^-e[[:space:]])" /env/requirements-lock.txt >/dev/null; then
            echo "[ERROR] requirements-lock.txt still contains local project path" >&2
            exit 1
        fi

        echo "[DONE] $(wc -l < /env/requirements-lock.txt) lines written to /env/requirements-lock.txt"
    '

echo "[DONE] lock generated: $LOCK_FILE"