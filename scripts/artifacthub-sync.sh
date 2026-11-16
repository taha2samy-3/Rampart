#!/usr/bin/env bash
set -euo pipefail

# Load credentials from .env.artifacthub if present
if [ -f .env.artifacthub ]; then
  # shellcheck disable=SC1091
  source .env.artifacthub
fi

KEY_ID="${ARTIFACTHUB_API_KEY_ID:-}"
KEY_SECRET="${ARTIFACTHUB_API_KEY_SECRET:-}"

if [ -z "$KEY_ID" ] || [ -z "$KEY_SECRET" ]; then
  echo "Error: ARTIFACTHUB_API_KEY_ID and ARTIFACTHUB_API_KEY_SECRET must be set."
  echo "You can set them in .env.artifacthub or export them in your shell."
  exit 1
fi

echo "Verifying Artifact Hub API Key..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "https://artifacthub.io/api/v1/user/profile" \
  -H "X-API-KEY-ID: ${KEY_ID}" \
  -H "X-API-KEY-SECRET: ${KEY_SECRET}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  echo "Artifact Hub authentication successful (HTTP $HTTP_CODE)."
  echo "$BODY"
else
  echo "Artifact Hub API response (HTTP $HTTP_CODE): $BODY"
fi
