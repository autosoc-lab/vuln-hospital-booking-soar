#!/usr/bin/env bash
# Shuffle 워크플로 자동 import — 재배포 시 workflows/*.json 을 복원한다.
# shuffle 모듈 user_data 가 `docker compose up -d` 이후 이 스크립트를 호출한다.
#   bash /opt/soar/bootstrap-import.sh
# 참고: Shuffle API 는 버전을 타므로, 실패하면 UI(Workflows -> Import)로 수동 import 하면 된다.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WF_DIR="$HERE/workflows"
ENV_FILE="$HERE/.env"
SHUFFLE_URL="http://localhost:3001"

USERNAME="admin"; PASSWORD=""
if [ -f "$ENV_FILE" ]; then
  U="$(grep -E '^SHUFFLE_DEFAULT_USERNAME=' "$ENV_FILE" | cut -d= -f2-)"; [ -n "$U" ] && USERNAME="$U"
  PASSWORD="$(grep -E '^SHUFFLE_DEFAULT_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
fi

log(){ echo "[bootstrap-import] $*"; }

# 1) 백엔드가 응답할 때까지 대기 (최대 5분)
for i in $(seq 1 60); do
  curl -sf "$SHUFFLE_URL/" >/dev/null 2>&1 && break
  sleep 5
done

# 2) 로그인 -> apikey
RESP="$(curl -s -X POST "$SHUFFLE_URL/api/v1/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")"
APIKEY="$(printf '%s' "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("apikey",""))' 2>/dev/null || true)"
if [ -z "$APIKEY" ]; then log "로그인/APIKEY 실패. 응답: $RESP"; log "UI(Workflows->Import)로 수동 import 하세요."; exit 1; fi
log "로그인 성공"

# 3) 기존 워크플로 목록 (중복 import 방지)
EXISTING="$(curl -s "$SHUFFLE_URL/api/v1/workflows" -H "Authorization: Bearer $APIKEY")"

# 4) workflows/*.json import
shopt -s nullglob
for f in "$WF_DIR"/*.json; do
  NAME="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("name",""))' "$f" 2>/dev/null)"
  if printf '%s' "$EXISTING" | grep -q "\"name\":\"$NAME\""; then
    log "이미 존재: $NAME (skip)"; continue
  fi
  log "import: $NAME"
  R="$(curl -s -X POST "$SHUFFLE_URL/api/v1/workflows" \
        -H "Authorization: Bearer $APIKEY" -H 'Content-Type: application/json' \
        --data-binary "@$f")"
  NEWID="$(printf '%s' "$R" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))' 2>/dev/null || true)"
  log "  -> workflow id=$NEWID"

  # 웹훅 트리거 start + 워크플로 저장(활성화) 시도
  HOOKID="$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
for t in d.get("triggers",[]):
    if t.get("trigger_type")=="WEBHOOK": print(t.get("id","")); break' "$f" 2>/dev/null || true)"
  if [ -n "$HOOKID" ]; then
    curl -s "$SHUFFLE_URL/api/v1/hooks/webhook_$HOOKID/start" -H "Authorization: Bearer $APIKEY" >/dev/null 2>&1 || true
    log "  -> webhook start 시도 (hook=$HOOKID)"
  fi
done
log "완료. UI에서 워크플로가 Enable 인지, Webhook 이 Running 인지 확인하세요."
