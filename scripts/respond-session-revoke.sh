#!/usr/bin/env bash
# SSRF->IMDS 자격증명 탈취 / SSE-C 반출 자동 대응 - 앱 EC2 role의 STS 세션 강제 무효화.
# 탈취되는 게 IAM 액세스키가 아니라 인스턴스 프로파일의 임시 세션이라
# iam:UpdateAccessKey가 안 먹힌다 - TokenIssueTime 조건부 Deny-all 인라인 정책을
# 붙여서 이미 발급된 세션을 강제로 무효화한다(AWS 콘솔 "Revoke active sessions"와 동일).
# 100013/100033(승인 후 호출)과 100014/100034(승인 없이 호출) 양쪽 브랜치가 이 스크립트를
# 그대로 공유한다 - 승인 여부는 Shuffle 워크플로 쪽에서 이미 걸러진 뒤 호출되므로 여기선
# 재확인하지 않는다.
#
# 주의: 앱 EC2가 쓰는 현재 세션까지 같이 막히므로, 실습/테스트 후에는 반드시
#   aws iam delete-role-policy --role-name <role> --policy-name shuffle-emergency-revoke
# 로 정리해야 앱이 정상 동작한다.
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
: "${SOAR_APP_EC2_ROLE_NAME:?missing SOAR_APP_EC2_ROLE_NAME}"

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "[soar] start session revoke at $timestamp"
echo "[soar] app ec2 role: $SOAR_APP_EC2_ROLE_NAME"
echo "[soar] all sessions issued before $timestamp will be denied"

policy_document=$(cat <<POLICY_EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "DateLessThan": {"aws:TokenIssueTime": "$timestamp"}
    }
  }]
}
POLICY_EOF
)

aws iam put-role-policy \
  --region "$AWS_REGION" \
  --role-name "$SOAR_APP_EC2_ROLE_NAME" \
  --policy-name "shuffle-emergency-revoke" \
  --policy-document "$policy_document"

echo "[soar] deny-all inline policy 'shuffle-emergency-revoke' attached - active sessions revoked"
echo "[soar] NOTE: remove with 'aws iam delete-role-policy --role-name $SOAR_APP_EC2_ROLE_NAME --policy-name shuffle-emergency-revoke' once incident is resolved, or app EC2 will stay broken"
echo "[soar] done"
