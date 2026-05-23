#!/usr/bin/env bash
set -euo pipefail

IMAGE="${RINHA_IMAGE:-ghcr.io/rafaelcoelhox/eu-sou-o-ze-pamonha:pmhh}"

docker buildx build \
  --platform linux/amd64 \
  -t "$IMAGE" \
  --push \
  .
