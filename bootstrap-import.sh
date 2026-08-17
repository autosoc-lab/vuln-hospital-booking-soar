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

USERNAME="admin"; PASSWORD=""; DISCORD_WEBHOOK_URL=""; SOAR_RESPONSE_API_URL=""
if [ -f "$ENV_FILE" ]; then
  U="$(grep -E '^SHUFFLE_DEFAULT_USERNAME=' "$ENV_FILE" | cut -d= -f2-)"; [ -n "$U" ] && USERNAME="$U"
  PASSWORD="$(grep -E '^SHUFFLE_DEFAULT_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
  # Discord 웹훅 URL(시크릿). shuffle 모듈 user_data가 tfvars 값을 .env에 넣어준다.
  # 값이 있으면 import 직전 워크플로 JSON의 Discord url(인증필드)에 주입한다 — 인증필드는
  # export 시 값이 비워지므로, 재배포마다 이 방식으로 다시 채워야 Discord 알림이 나간다.
  DISCORD_WEBHOOK_URL="$(grep -E '^DISCORD_WEBHOOK_URL=' "$ENV_FILE" | cut -d= -f2-)"
  SOAR_RESPONSE_API_URL="$(grep -E '^SOAR_RESPONSE_API_URL=' "$ENV_FILE" | cut -d= -f2-)"
fi

# Shuffle은 import마다 workflow/webhook id를 새로 생성한다. 하지만 /hooks/new payload의
# id는 우리가 지정할 수 있으므로, 웹훅 hook을 이 고정 id로 만든다 → Wazuh가 하드코딩한
# URL(webhook_<이 id>)과 항상 일치. 이 값은 infra의 wazuh 모듈 shuffle_webhook_hook_id와
# 반드시 동일해야 한다.
FIXED_HOOK_ID="8e84e673-e96b-4807-956d-92a05fb06ed3"

log(){ echo "[bootstrap-import] $*"; }

# 1) 백엔드 준비 대기. 주의: 로그인(/login)은 Shuffle의 레이트리밋 대상이라
#    준비 확인용으로 반복 호출하면 'Too many requests'를 유발한다. 그래서 준비여부는
#    레이트리밋 없는 GET 엔드포인트로 '백엔드가 502를 안 낼 때까지'만 확인한다.
#    (프론트 nginx의 '/'는 백엔드가 안 떠도 200을 주므로 준비 판단에 쓰면 안 됨.)
log "백엔드 준비 대기..."
for i in $(seq 1 90); do
  CODE="$(curl -s -o /dev/null -w '%{http_code}' "$SHUFFLE_URL/api/v1/getenvironments" 2>/dev/null || echo 000)"
  if [ "$CODE" != "502" ] && [ "$CODE" != "000" ] && [ "$CODE" != "504" ]; then
    log "백엔드 응답 시작 (HTTP $CODE, ${i}회)"; break
  fi
  sleep 10
done

# 2) 로그인. 이 Shuffle 버전은 응답 바디에 apikey를 주지 않고(로그인은 success:true만
#    반환) 세션 쿠키로 인증한다 — UI 로그인과 동일. 그래서 쿠키를 항아리에 저장해
#    이후 요청에 재사용한다. 레이트리밋 주의: 넉넉한 간격 + 'Too many requests' 시 60s 백오프.
COOKIE_JAR="$(mktemp)"
LOGGED_IN=""
for i in $(seq 1 12); do
  RESP="$(curl -s -c "$COOKIE_JAR" -X POST "$SHUFFLE_URL/api/v1/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")"
  if printf '%s' "$RESP" | grep -q '"success":[[:space:]]*true'; then LOGGED_IN=1; log "로그인 성공 (시도 ${i}회)"; break; fi
  if printf '%s' "$RESP" | grep -qi "too many requests"; then
    log "로그인 레이트리밋 감지 — 60초 대기 후 재시도 (${i}/12)"; sleep 60
  else
    log "로그인 대기중 (${i}/12): $(printf '%s' "$RESP" | head -c 120)"; sleep 20
  fi
done
if [ -z "$LOGGED_IN" ]; then log "로그인 실패. 마지막 응답: $(printf '%s' "$RESP" | head -c 200)"; log "UI(Workflows->Import)로 수동 import 하세요."; exit 1; fi

# 3) 기존 워크플로 목록 (중복 import 방지)
EXISTING="$(curl -s -b "$COOKIE_JAR" "$SHUFFLE_URL/api/v1/workflows")"

# 4) workflows/*.json import
shopt -s nullglob
for f in "$WF_DIR"/*.json; do
  NAME="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("name",""))' "$f" 2>/dev/null)"
  if printf '%s' "$EXISTING" | grep -q "\"name\":\"$NAME\""; then
    log "이미 존재: $NAME (skip)"; continue
  fi
  log "import: $NAME"
  SRC="$f"
  if [ -n "$DISCORD_WEBHOOK_URL" ]; then
    PATCHED="$(mktemp)"
    N="$(python3 - "$f" "$DISCORD_WEBHOOK_URL" "$PATCHED" <<'PYEOF'
import json,sys
src,url,out=sys.argv[1],sys.argv[2],sys.argv[3]
d=json.load(open(src)); n=0
for a in d.get("actions",[]):
    if (a.get("app_name") or "").lower()=="discord" and a.get("label")!="SOAR_Response_API":
        for prm in a.get("parameters",[]):
            if prm.get("name")=="url": prm["value"]=url; n+=1
json.dump(d,open(out,"w")); print(n)
PYEOF
)"
    if [ "$N" != "0" ] && [ -n "$N" ]; then SRC="$PATCHED"; log "  -> Discord url 주입 (${N}곳)"; fi
  fi
  if [ -n "$SOAR_RESPONSE_API_URL" ]; then
    PATCHED="$(mktemp)"
    N="$(python3 - "$SRC" "$SOAR_RESPONSE_API_URL" "$PATCHED" <<'PYEOF'
import json,sys
src,url,out=sys.argv[1],sys.argv[2],sys.argv[3]
d=json.load(open(src)); n=0
for a in d.get("actions",[]):
    if a.get("label")=="SOAR_Response_API":
        for prm in a.get("parameters",[]):
            if prm.get("name")=="url": prm["value"]=url; n+=1
json.dump(d,open(out,"w")); print(n)
PYEOF
)"
    if [ "$N" != "0" ] && [ -n "$N" ]; then SRC="$PATCHED"; log "  -> SOAR response API url 주입 (${N}곳)"; fi
  fi
  R="$(curl -s -b "$COOKIE_JAR" -X POST "$SHUFFLE_URL/api/v1/workflows" \
        -H 'Content-Type: application/json' \
        --data-binary "@$SRC")"
  NEWID="$(printf '%s' "$R" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))' 2>/dev/null || true)"
  log "  -> workflow id=$NEWID"

  # 웹훅 활성화(Running). Shuffle은 /hooks/new 로 hook을 만들면서 start시킨다
  # (구버전 경로 /hooks/webhook_<id>/start 는 이 버전에서 404). payload의 id를
  # FIXED_HOOK_ID로 지정해 Wazuh 하드코딩 URL과 일치시킨다. start(진입 액션 id)와
  # 웹훅 이름/환경은 워크플로 JSON에서 읽는다(import해도 보존됨). workflow는 방금 import된 NEWID.
  META="$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
name="Webhook"; env="Shuffle"
for t in d.get("triggers",[]):
    if t.get("trigger_type")=="WEBHOOK":
        name=t.get("name") or name; env=t.get("environment") or env
print((d.get("start","") or "")+"\t"+name+"\t"+env)' "$f" 2>/dev/null || true)"
  START="$(printf '%s' "$META" | cut -f1)"
  WHNAME="$(printf '%s' "$META" | cut -f2)"
  WHENV="$(printf '%s' "$META" | cut -f3)"
  if [ -n "$NEWID" ] && [ -n "$START" ]; then
    HRESP="$(curl -s -b "$COOKIE_JAR" -X POST "$SHUFFLE_URL/api/v1/hooks/new" -H 'Content-Type: application/json' \
      -d "{\"name\":\"$WHNAME\",\"type\":\"webhook\",\"id\":\"$FIXED_HOOK_ID\",\"auth\":\"\",\"custom_response\":\"\",\"environment\":\"$WHENV\",\"start\":\"$START\",\"version\":\"v1\",\"version_timeout\":15,\"workflow\":\"$NEWID\"}")"
    if printf '%s' "$HRESP" | grep -q '"success"[: ]*true'; then
      log "  -> 웹훅 자동 start 완료 (hook id=$FIXED_HOOK_ID)"
    else
      log "  -> 웹훅 start 실패: $(printf '%s' "$HRESP" | head -c 150) — UI에서 Start 필요"
    fi
  else
    log "  -> NEWID/start 없음 → 웹훅 자동 start 생략 (UI에서 Start 필요)"
  fi
done
log "완료. UI에서 워크플로가 Enable 인지, Webhook 이 Running 인지 확인하세요."
