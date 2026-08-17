#!/usr/bin/env bash
# SSE-C 랜섬웨어 체인 자동 대응 - lifecycle 정책 원복.
# 되돌리기 쉽고 부작용이 거의 없는 조치라 승인 없이 자동 실행한다 (100031/100032 브랜치).
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$HERE/.env}"

if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

: "${AWS_REGION:=ap-northeast-2}"
: "${SOAR_DOCUMENTS_BUCKET:?missing SOAR_DOCUMENTS_BUCKET}"

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "[soar] start lifecycle revert at $timestamp"
echo "[soar] documents bucket: $SOAR_DOCUMENTS_BUCKET"

echo "[soar] snapshot current lifecycle configuration (may not exist)"
aws s3api get-bucket-lifecycle-configuration \
  --region "$AWS_REGION" \
  --bucket "$SOAR_DOCUMENTS_BUCKET" \
  > "/tmp/soar-lifecycle-before-${timestamp//:/}.json" 2>/dev/null || true

echo "[soar] remove lifecycle configuration entirely"
# put-bucket-lifecycle-configuration with an empty Rules list is rejected by S3
# (MalformedXML) - to fully remove the malicious auto-delete rule, the lifecycle
# configuration itself must be deleted, not replaced with an empty one.
aws s3api delete-bucket-lifecycle \
  --region "$AWS_REGION" \
  --bucket "$SOAR_DOCUMENTS_BUCKET"

echo "[soar] lifecycle reverted - auto-delete rule removed"
echo "[soar] done"
