#!/bin/sh
# TurboShield Dashboard — bootstrap
set -e
echo "[TurboShield] installing deps..."
pip install --quiet --no-cache-dir fastapi "uvicorn[standard]" psutil python-multipart 2>&1 | tail -2
# docker CLI untuk reload WAF (via mounted socket)
if ! command -v docker >/dev/null 2>&1; then
  echo "[TurboShield] installing docker-cli..."
  apt-get update -qq && apt-get install -y -qq docker.io >/dev/null 2>&1 || \
  (apt-get install -y -qq curl >/dev/null 2>&1; curl -sSL https://download.docker.com/linux/static/stable/x86_64/docker-27.3.1.tgz | tar xz -C /tmp && cp /tmp/docker/docker /usr/local/bin/) || true
fi
echo "[TurboShield] starting uvicorn on :8181"
exec uvicorn app:app --host 0.0.0.0 --port 8181 --workers 1
