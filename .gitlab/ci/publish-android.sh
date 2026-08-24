#!/usr/bin/env bash
# Uploads the Android APK + checksum to the Generic Package Registry and
# prints the stable (never-expiring) product link.
set -euo pipefail

VERSION=$(grep '^version' neuron-encrypt/Cargo.toml | head -1 | cut -d'"' -f2)
NAME=$(ls neuron-encrypt-*-android.apk | head -1)
BASE="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/neuron-encrypt/${VERSION}"

curl --fail -H "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file SHA256SUMS-android.txt "$BASE/SHA256SUMS-android.txt" || true
curl --fail -H "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file $NAME "$BASE/$NAME"

echo ""
echo "==============================================================="
echo " PRODUCT LINK (stable):"
echo "   $BASE/$NAME"
echo " Browse: ${CI_PROJECT_URL}/-/packages/generic/neuron-encrypt/${VERSION}"
echo "==============================================================="
