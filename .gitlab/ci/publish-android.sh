#!/usr/bin/env bash
# Uploads the Android APK + checksum to the Generic Package Registry and
# prints the stable (never-expiring) product link.
# Usage: publish-android.sh <apk-filename> <version>
set -euo pipefail

APK_NAME="${1:?Usage: publish-android.sh <apk-filename> <version>}"
VERSION="${2:?Usage: publish-android.sh <apk-filename> <version>}"
BASE="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/neuron-encrypt/${VERSION}"
LATEST_BASE="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/neuron-encrypt/latest"

# ── versioned upload ───────────────────────────────────────────────────────────
curl --fail -H "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file SHA256SUMS-android.txt "$BASE/SHA256SUMS-android.txt" || true
curl --fail -H "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file "$APK_NAME" "$BASE/$APK_NAME"

# ── 'latest' alias (so direct-download links don't need version in the URL) ───
curl --fail -H "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file "$APK_NAME" \
  "$LATEST_BASE/neuron-encrypt-latest-android.apk" \
  || echo "WARN: latest alias upload failed (registry disabled?)"
curl --fail -H "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file SHA256SUMS-android.txt \
  "$LATEST_BASE/SHA256SUMS-android.txt" || true

echo ""
echo "==============================================================="
echo " PRODUCT LINK (stable):"
echo "   $BASE/$APK_NAME"
echo " LATEST LINK:"
echo "   $LATEST_BASE/neuron-encrypt-latest-android.apk"
echo " Browse: ${CI_PROJECT_URL}/-/packages/generic/neuron-encrypt/${VERSION}"
echo "==============================================================="
