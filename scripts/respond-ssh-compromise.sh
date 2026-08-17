#!/usr/bin/env bash
# Leaked SSH key -> EC2 compromise -> medical data exfiltration response helper.
# Run on the Shuffle EC2 host. Terraform injects the required SOAR_* values into /opt/soar/.env
# and grants this instance profile permissions only for the lab app EC2, lab leaked IAM user,
# and lab documents bucket.
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
: "${SOAR_APP_INSTANCE_TAG_NAME:?missing SOAR_APP_INSTANCE_TAG_NAME}"
: "${SOAR_QUARANTINE_SECURITY_GROUP_ID:?missing SOAR_QUARANTINE_SECURITY_GROUP_ID}"
: "${SOAR_LEAKED_S3_KEY_USER_NAME:?missing SOAR_LEAKED_S3_KEY_USER_NAME}"
: "${SOAR_DOCUMENTS_BUCKET:?missing SOAR_DOCUMENTS_BUCKET}"

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

SOAR_APP_INSTANCE_ID="$(aws ec2 describe-instances \
  --region "$AWS_REGION" \
  --filters "Name=tag:Name,Values=$SOAR_APP_INSTANCE_TAG_NAME" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
  --query 'Reservations[].Instances[].InstanceId' \
  --output text | awk '{print $1}')"

if [ -z "$SOAR_APP_INSTANCE_ID" ] || [ "$SOAR_APP_INSTANCE_ID" = "None" ]; then
  echo "[soar] app instance not found by tag Name=$SOAR_APP_INSTANCE_TAG_NAME" >&2
  exit 1
fi

echo "[soar] start ssh compromise response at $timestamp"
echo "[soar] app instance: $SOAR_APP_INSTANCE_ID"
echo "[soar] quarantine sg: $SOAR_QUARANTINE_SECURITY_GROUP_ID"
echo "[soar] leaked iam user: $SOAR_LEAKED_S3_KEY_USER_NAME"
echo "[soar] documents bucket: $SOAR_DOCUMENTS_BUCKET"

echo "[soar] collect EC2 state"
aws ec2 describe-instances \
  --region "$AWS_REGION" \
  --instance-ids "$SOAR_APP_INSTANCE_ID" \
  --output json > "/tmp/soar-ec2-${SOAR_APP_INSTANCE_ID}.json"

echo "[soar] isolate EC2 with quarantine security group"
aws ec2 modify-instance-attribute \
  --region "$AWS_REGION" \
  --instance-id "$SOAR_APP_INSTANCE_ID" \
  --groups "$SOAR_QUARANTINE_SECURITY_GROUP_ID"

echo "[soar] tag compromised instance"
aws ec2 create-tags \
  --region "$AWS_REGION" \
  --resources "$SOAR_APP_INSTANCE_ID" \
  --tags \
    Key=SOARStatus,Value=Quarantined \
    Key=SOARReason,Value=LeakedSSHKeyMedicalDataExfil \
    Key=SOARUpdatedAt,Value="$timestamp" || true

echo "[soar] disable leaked IAM access keys"
aws iam list-access-keys \
  --user-name "$SOAR_LEAKED_S3_KEY_USER_NAME" \
  --query 'AccessKeyMetadata[].AccessKeyId' \
  --output text |
while read -r key_id; do
  [ -z "$key_id" ] && continue
  aws iam update-access-key \
    --user-name "$SOAR_LEAKED_S3_KEY_USER_NAME" \
    --access-key-id "$key_id" \
    --status Inactive
  echo "[soar] disabled access key: $key_id"
done

echo "[soar] collect recent CloudTrail S3 activity for impact review"
aws cloudtrail lookup-events \
  --region "$AWS_REGION" \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$SOAR_DOCUMENTS_BUCKET" \
  --max-results 50 \
  --output json > "/tmp/soar-cloudtrail-documents-${SOAR_DOCUMENTS_BUCKET}.json" || true

echo "[soar] done"
