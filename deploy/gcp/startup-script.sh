#!/usr/bin/env bash
# Example GCE startup: install Docker, pull API image, run with env file.
# 1. Put /opt/quantumshield/.env on the VM (chmod 600).
# 2. Metadata: add this script as startup-script or store in bucket and curl it.
# 3. Replace IMAGE with your Artifact Registry URL.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y docker.io
systemctl enable docker
systemctl start docker

IMAGE="${QUANTUMSHIELD_IMAGE:-us-central1-docker.pkg.dev/PROJECT_ID/quantumshield/api:latest}"
ENV_FILE="${QUANTUMSHIELD_ENV_FILE:-/opt/quantumshield/.env}"

mkdir -p /opt/quantumshield
docker pull "$IMAGE" || true
docker rm -f quantumshield-api 2>/dev/null || true
docker run -d --name quantumshield-api --restart unless-stopped -p 8000:8000 \
  --env-file "$ENV_FILE" \
  "$IMAGE"
