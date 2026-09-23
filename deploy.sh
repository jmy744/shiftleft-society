#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")"
command -v docker >/dev/null || { echo "Docker is required" >&2; exit 1; }
test -f .env || { echo "Copy .env.example to .env and configure it first" >&2; exit 1; }

docker compose --profile production config --quiet
docker compose --profile production build --pull
docker compose --profile production up -d --remove-orphans
docker compose exec -T app python migrate_v4.py
docker compose ps
echo "Deployment complete. Verify: https://${DOMAIN:-localhost}/health"
