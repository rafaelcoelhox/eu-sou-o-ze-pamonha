#!/usr/bin/env bash
set -euo pipefail

curl -fsS http://localhost:9999/ready
printf '\n'
curl -fsS -X POST http://localhost:9999/fraud-score \
  -H 'Content-Type: application/json' \
  --data @<(jq '.[0]' resources/example-payloads.json)
printf '\n'
