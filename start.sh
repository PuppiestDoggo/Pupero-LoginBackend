#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
[ -d .venv ] && source .venv/bin/activate || true
export $(grep -v '^#' .env | xargs -d '\n' -0 2>/dev/null || true)
uvicorn app.main:app --host 0.0.0.0 --port "${LOGIN_PORT:-8001}"