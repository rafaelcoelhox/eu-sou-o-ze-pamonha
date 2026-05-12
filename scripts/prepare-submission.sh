#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-./submission-build}"
mkdir -p "$OUT"
cp submission/docker-compose.yml "$OUT/docker-compose.yml"
cp submission/info.json "$OUT/info.json"
echo "Arquivos de submissão copiados para: $OUT"
echo "Lembre-se: a branch submission deve conter apenas esses arquivos."
