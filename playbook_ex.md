# SOAR 플레이북 설계

Shuffle 워크플로는 `workflows/Wazuh Alert Router.json`으로 저장되어 있고 Terraform 배포 시
자동 import된다. 이 문서는 import된 워크플로가 어떤 조건으로 어떤 대응을 해야 하는지와,
유출 SSH 키 기반 EC2 침해 및 의료 데이터 유출 시나리오의 운영 런북을 정리한다.

## 1. 데이터 흐름

```
[app EC2 auditd/FIM/앱로그]  [CloudTrail/VPC Flow Logs/GuardDuty findings -> S3]
              \                              /
               \                            /  (wodle aws-s3가 주기적으로 읽어감)
                v                          v
                     Wazuh 매니저 (rule/decoder 매칭)
                                |
                                | level >= 6 인 알림만 (enable-shuffle-integration.sh 기본값)
                                v
                custom-shuffle integration (POST 전체 alert JSON)
                                |
                                v
                Shuffle 웹훅 트리거 -> "Wazuh Alert Router" 워크플로
                                |
                    (rule.groups / rule.level 로 분기)
                                |
                +---------------+---------------+
                v               v               v
            Discord/이메일 알림  케이스 생성      AWS 자동조치
```

핵심은 **호스트 기반 이벤트(auditd, FIM, 앱 요청 로그)와 AWS 로그 기반 이벤트(CloudTrail,
VPC Flow Logs, GuardDuty)가 전부 Wazuh를 거쳐 같은 웹훅 하나로 들어온다**는 것. Shuffle
쪽에서 별도로 AWS를 직접 붙일 필요가 없다 — Wazuh가 이미 그 통합 지점 역할을 한다.

## 2. 알림 라우팅 테이블

`vuln-hospital-booking-infra`의 `modules/wazuh/files/local_rules.xml`,
`vuln_hospital_ssh_compromise.xml`에 정의된 커스텀 룰 + Wazuh 기본 AWS 룰셋 기준.

| 룰 그룹 / ID | 레벨 | 의미 | 소스 | 권장 조치 (1단계: 알림만) |
|---|---|---|---|---|
| `ssrf` (100011) | 10 | SSRF 의심 (내부망/메타데이터 주소 요청) | 앱 로그(agent) | Slack #soc-alerts 알림 |
| `ssrf,attack_scenario` (100012) | 12 | 알려진 취약 엔드포인트 대상 SSRF | 앱 로그 | Slack, 심각도 High |
| `ssrf,credential_access,critical` (100013) | 14 | IMDS 자격증명 경로 조회 시도 (200 확증 전) | 앱 로그 | **케이스 생성 + 긴급 알림 + 사람 승인 후 세션 revoke** (2단계 구현됨, [6-2](#6-2-rule-100013100033-브랜치--세션-revoke-high-사람-승인-필수) 참고) |
| `ssrf,credential_access,critical` (100014) | 15 | IMDS 자격증명 탈취 확증 (200 응답) | 앱 로그 | **케이스 생성 + 긴급 알림 + 완전자동 세션 revoke** (2단계 구현됨, [6-3](#6-3-rule-100014100034-브랜치--세션-revoke-critical-완전자동) 참고) |
| `s3_exfil` (100021) | 12 | 문서 버킷 대량 다운로드(sync 유출 의심) | CloudTrail(S3 데이터 이벤트) | 케이스 생성 + 알림 |
| `s3_ransomware` (100030/100031) | 10~12 | SSE-C 재암호화 / lifecycle 자동삭제 설정 (Codefinger 패턴) | CloudTrail | 100030: 케이스 생성 + 긴급 알림 / **100031: 완전자동 lifecycle 원복** (2단계 구현됨, [6-1](#6-1-rule-100031-브랜치--lifecycle-원복-완전자동-승인-불필요) 참고) |
| `s3_ransomware,attack_scenario,critical` (100032) | 15 | 같은 버킷에서 SSE-C 재암호화 직후 lifecycle 변경 - 상관분석 확증 (정상 운영으로는 안 나오는 조합) | CloudTrail | **완전자동 lifecycle 원복 + 긴급 알림** — 100031과 동일 조치, [6-1](#6-1-rule-100031-브랜치--lifecycle-원복-완전자동-승인-불필요) 참고 (같은 로그가 100031 대신 100032로 발화하므로 Filter가 둘 다 잡아야 함) |
| `s3_ransomware,s3_exfil` (100033) | 13 | SSE-C 커스텀 키로 문서 버킷 객체 조회 - 반출 정황(단독 발화) | CloudTrail | **케이스 생성 + 긴급 알림 + 사람 승인 후 세션 revoke** (2단계 구현됨, [6-2](#6-2-rule-100013100033-브랜치--세션-revoke-high-사람-승인-필수) 참고) |
| `s3_ransomware,attack_scenario,critical` (100034) | 15 | 재암호화→lifecycle→SSE-C 반출까지 전 단계 상관분석 확증 | CloudTrail | **완전자동 세션 revoke + 긴급 알림** (2단계 구현됨, [6-3](#6-3-rule-100014100034-브랜치--세션-revoke-critical-완전자동) 참고) |
| `log_tampering` (100040~100045) | 9~12 | CloudTrail/Flow Logs 중지·삭제·정책변경 | CloudTrail | **케이스 생성 + Slack 긴급 알림** (방어회피 = 이미 침해 진행 중일 가능성 높음) |
| `vpcflow,recon` (100052) | 10 | 포트스캔/정찰 의심 | VPC Flow Logs | Slack 알림 |
| `vpcflow,exfil` (100054) | 10 | 대용량 외부 반출 의심 | VPC Flow Logs | 케이스 생성 + Slack |
| `ssh_compromise,*` (100170~100183) | 5~15 | 유출 SSH키 침해 -> 정찰 -> 권한상승 -> 데이터반출 체인 | auditd(agent) | 레벨 12 이상만 케이스 생성, 그 미만은 로그만 |
| `attack_scenario,privilege_escalation,critical` (100179/100180) | 15 | 권한상승 확증 (체인 상관분석 룰) | auditd | **케이스 생성 + Slack 긴급 알림** |
| `aws`, `guardduty` (Wazuh 기본 룰셋) | 룰마다 다름 | GuardDuty finding (정찰/자격증명침해/C2/크립토재킹 등) | GuardDuty -> S3 | 레벨 기준으로 Slack 알림 |

레벨 임계값은 `enable-shuffle-integration.sh` 실행 시 두 번째 인자로 조절 가능
(기본 6). 처음엔 6으로 넓게 받고, 알림이 너무 많으면 8~10으로 올리는 걸 권장.

## 3. "Wazuh Alert Router" 워크플로 조건

Webhook 노드 뒤에 **Shuffle Tools** 앱의 **Filter** 액션을 연결해서 분기한다. Filter의
조건식에서 다음 필드를 참조할 수 있다.
   - `$exec.rule.level` — 정수 레벨
   - `$exec.rule.groups` — 배열, 예: `["ssrf","credential_access","critical"]`
   - `$exec.rule.description`, `$exec.rule.id`
   - `$exec.agent.name` — 어느 EC2에서 왔는지 (app / wazuh 자체 등)
분기:

- **일반 알림** (`rule.level < 12`): Discord/Email 알림. 메시지에 `$exec.rule.description`,
  `$exec.rule.level`, `$exec.agent.name`, `$exec.full_log` 포함.
- **긴급 알림** (`rule.level >= 12` 또는 `rule.groups`에 `critical` 포함): Discord 긴급 알림
  및 케이스 생성.
- **SSH 침해 자동 대응** (`rule.level >= 15` 이고, SSH 침해 룰 범위에서 `rule.id`가
  `100174`, `100179`, `100180` 중 하나): 앱 EC2 격리, 실습용 유출 IAM 키 비활성화,
  CloudTrail/S3 영향도 확인.

## 4. 유출 SSH 키/의료 데이터 유출 대응 런북

권장 자동 대응 순서:

1. 증거 보존: Wazuh alert 원문, EC2 describe 결과, 최근 CloudTrail S3 이벤트를 저장한다.
2. 확산 차단: 앱 EC2에 격리 SG만 적용해 인바운드/아웃바운드를 차단한다.
3. 자격증명 무력화: 실습용 유출 IAM 사용자의 access key를 `Inactive`로 전환한다.
4. 영향도 확인: 문서 버킷의 `GetObject`, `PutObject`, SSE-C, lifecycle 변경 이벤트를 확인한다.
5. 통보: Discord/케이스에 룰 ID, 에이전트, 인스턴스 ID, 버킷명, 조치 결과를 기록한다.

Terraform apply 후 Shuffle EC2에는 `soar-response-api.service`가 함께 배포된다. Shuffle
GUI의 `SOAR_Response_API` 노드는 `level >= 15` 이벤트에서 이 API를 호출한다. API는 다시
룰 ID를 확인한 뒤 다음 헬퍼를 실행한다.

```bash
sudo /opt/soar/scripts/respond-ssh-compromise.sh
```

이 스크립트는 `/opt/soar/.env`의 `SOAR_APP_INSTANCE_TAG_NAME`,
`SOAR_QUARANTINE_SECURITY_GROUP_ID`, `SOAR_LEAKED_S3_KEY_USER_NAME`,
`SOAR_DOCUMENTS_BUCKET` 값을 사용한다.

## 5. 테스트

**Wazuh 쪽에서 강제 발화:**
```bash
# 매니저에서 alerts.json 최근 알림 확인
tail -f /var/ossec/logs/alerts/alerts.json
# integration 호출/에러 로그
tail -f /var/ossec/logs/integrations.log
```

**Shuffle 웹훅만 독립적으로 테스트 (Wazuh 없이):**
```bash
curl -X POST 'http://<shuffle-ip>:3001/api/v1/hooks/webhook_XXXXXXXX' \
  -H 'content-type: application/json' \
  -d '{"rule":{"level":15,"id":"100180","groups":["attack_scenario","privilege_escalation","critical"],"description":"권한 상승 확증: 대화형 헬퍼 변조 후 root 소유 표식 파일 생성"},"agent":{"name":"app-ec2"}}'
```
Shuffle UI의 워크플로 화면에서 **Executions** 탭을 보면 위 테스트 요청이 실행되고
분기를 어떻게 탔는지 노드별로 확인할 수 있다.

**실제 공격 재현으로 종단 테스트:** `vuln-hospital-booking/case-study/SSRF.md`,
`SQLi.md`, `RCE.md`, `SSE-C.md`에 정리된 시나리오를 실행하면 이 표의 룰들이 실제로
발화한다.

## 6. 2단계: AWS 자동조치 (구현됨 — SSRF -> SSE-C 랜섬웨어 체인용)

**자동조치 대상 선정 기준:** 기본적으로 `rule.level`이 **14 또는 15**인 알림만
자동조치(완전자동이든 승인형이든) 대상으로 삼는다. 그 미만은 1단계(알림/케이스
생성)로 남긴다 — 오탐 시 실제 AWS 자원을 잘못 건드리는 리스크를 심각도가 확실히
높은 알림으로만 한정하기 위함이다.

**예외: rule 100031 (level 10).** 심각도 기준으로는 대상이 아니지만, 판단 근거가
심각도가 아니라 "**되돌리기 쉽고 부작용이 거의 없음 + 몇 시간 안에 되돌릴 수 없게
되는 골든타임이 걸려있음**"이라 별도로 완전자동 대상에 포함해뒀다(6-1 참고). 새
자동조치를 추가할 때도 이 두 갈래 중 하나로 판단할 것: (a) level 14/15면 기본
대상, (b) level이 낮아도 100031처럼 명확히 안전+시간이 급한 조치면 개별 예외로
문서에 그 근거를 남기고 추가.

이 예외가 근본적으로 필요했던 이유는 100031이 정상 운영(문서 자동 보관/만료 정책
설정)으로도 뜰 수 있어 level을 낮게 유지해야 했기 때문이다. 이를 보완하기 위해
**100032**(같은 버킷에서 SSE-C 재암호화 직후 lifecycle 변경 — 정상 운영으로는
나올 수 없는 조합, [local_rules.xml:116](../vuln-hospital-booking-infra/modules/wazuh/files/local_rules.xml#L116))를
상관분석 룰로 추가했다. 이 룰은 기준(level 14/15)에 그대로 부합해서 별도 예외
문서화가 필요 없다 — 확증된 경우엔 로그가 100031이 아니라 100032로 발화하므로,
100031을 대상으로 하는 조치는 100032도 같이 잡아야 한다(6-1 참고).

SSH 침해 체인의 level 14/15 룰들(`100172`~`100180`)은 기준상으로는 자동조치
대상이지만, 아직 구체적인 조치가 설계/구현되지 않아 **지금은 1단계(알림만)로
남겨둔다.** 나중에 붙일 때는 6-5를 참고.

100013(level 14, SSRF→IMDS 조회 시도 — 200 확증 전 단계)은 별도 액션을 설계하지
않고 6-2 브랜치에 합류시켰다 — 100014와 같은 탈취 STS 세션이 IMDS 자격증명 경로를
노린 것뿐이라 필요한 조치(세션 revoke)가 동일하고, 확증 전 단계라 승인 게이트도
그대로 유효하기 때문이다.

**구현 방식 (중요 — 최초 설계에서 바뀜):** 처음엔 Shuffle의 범용 "AWS" 앱으로 직접
`put_role_policy`/`put_bucket_lifecycle_configuration`을 부르려 했는데, 실제 이
Shuffle 인스턴스의 앱 카탈로그에는 범용 AWS 앱도 AWS IAM 앱도 없고 AWS S3도
활성화가 정상적으로 안 붙었다(카탈로그/버전 문제로 추정). 그래서 기존
`SOAR_Response_API`(100174/100179/100180용, ssh-compromise 대응)와 완전히 같은
패턴으로 우회했다 — Shuffle은 그냥 **평범한 Http POST**만 로컬 API(`soar-response-api.py`,
Shuffle EC2 8088 포트)로 보내고, 실제 AWS 호출은 그 로컬 API가 EC2 인스턴스
프로파일 자격증명으로 별도 스크립트를 실행해서 처리한다. 이러면 Shuffle 쪽 앱
인증 설정이 아예 필요 없다.

`modules/shuffle/main.tf`의 `shuffle_ec2` role에는 아래 두 조치에 필요한 최소
권한이 붙어있다(둘 다 리소스를 특정 ARN 하나로 좁혀놓음 — 계정 전체가 아니라
documents 버킷/app EC2 role 딱 그거 하나만 건드릴 수 있음):

| Terraform 리소스 | 부여 액션 | 대상 |
|---|---|---|
| `aws_iam_role_policy.shuffle_lifecycle_revert` | `s3:GetLifecycleConfiguration`, `s3:PutLifecycleConfiguration` | documents 버킷 ARN |
| `aws_iam_role_policy.shuffle_revoke_session` | `iam:PutRolePolicy`, `iam:DeleteRolePolicy`, `iam:GetRolePolicy` | 앱 EC2 role(`ec2_ssm`) ARN |

`soar-response-api.py`는 경로별로 `rule_ids`/`min_level`/`require_group` 허용
목록을 갖는 `ROUTES` 딕셔너리 구조다(기존 ssh-compromise 라우트를 그대로 두고
아래 두 개를 추가):

| 경로 | 실행 스크립트 | 허용 rule.id |
|---|---|---|
| `/respond/lifecycle-revert` | `respond-lifecycle-revert.sh` | 100031, 100032 |
| `/respond/session-revoke` | `respond-session-revoke.sh` | 100013, 100014, 100033, 100034 |

승인 여부는 API가 아니라 **Shuffle 워크플로 쪽에서** 걸러야 한다 — API는 rule_id가
허용 목록에 있으면 무조건 실행한다(같은 이유로 100013/100033을 허용 목록에 넣어놔도,
아직 그쪽을 호출하는 Shuffle 브랜치가 없으면 실제로는 절대 안 불림 — 6-2 참고).

### 6-1. rule 100031/100032 브랜치 — lifecycle 원복 (완전자동, 승인 불필요, 구현 완료)

되돌리기 쉽고 부작용이 거의 없는 조치라 사람 승인 없이 자동화한다. documents 버킷은
versioning은 켜져 있지만 MFA Delete/Object Lock이 없어서([modules/app/main.tf:150](../vuln-hospital-booking-infra/modules/app/main.tf#L150)
참고), 이 lifecycle 룰이 실제로 실행되기 전(보통 며칠의 유예)이 복구 가능 여부가 걸린
골든타임이다 — 그래서 자동화 우선순위가 가장 높다.

**Shuffle에 실제로 구현된 노드/브랜치** (`workflows/Wazuh Alert Router.json`,
`Lifecycle_Revert` 액션):

1. `Change_Me` 뒤에 `Lifecycle_Revert`(Http POST) 노드, 대상
   `http://<shuffle 사설IP>:8088/respond/lifecycle-revert`, body에
   `$exec.rule`/`$exec.agent`/`$exec.full_log`를 그대로 실어 보낸다.
2. 브랜치 조건은 **`is`가 아니라 `contains`**를 쓴다 — 이 Shuffle 버전에서 `is`
   조건과 콤마로 여러 값을 나열하는 `in` 조건 둘 다 실제로는 매치가 안 되는 걸
   확인했다(겉으로는 저장되는데 실행 시 항상 스킵됨). `$exec.rule.id contains 100031`,
   `$exec.rule.id contains 100032` — **각각 별도 브랜치**로 만들어서 같은
   `Lifecycle_Revert` 노드로 연결한다(OR을 한 브랜치 안 여러 조건으로 표현하면
   AND로 묶여서 절대 안 걸린다 — 100031이면서 동시에 100032일 수는 없으므로).
3. `respond-lifecycle-revert.sh`는 `aws s3api delete-bucket-lifecycle`을 호출한다.
   처음엔 `put-bucket-lifecycle-configuration`을 빈 규칙(`{"Rules":[]}`)으로
   호출했는데 S3가 `MalformedXML`로 거부한다 — lifecycle을 완전히 제거하려면
   반드시 delete를 써야 한다.

**배포 시 주의:** `local_rules.xml`은 Wazuh 매니저가 **최초 부팅 시에만** S3에서
받아온다([modules/wazuh/main.tf](../vuln-hospital-booking-infra/modules/wazuh/main.tf) 참고).
이미 떠 있는 인스턴스는 `terraform apply`로 S3 오브젝트만 갱신해도 룰이 자동
반영되지 않는다 — Session Manager로 접속해서 아래를 수동으로 실행해야 100032가
실제로 발화한다:
```bash
sudo aws s3 cp "s3://<log_bucket_name>/wazuh-rules/local_rules.xml" /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```
Shuffle EC2 쪽 스크립트/`.env`도 마찬가지로 최초 부팅 시에만 심어지므로, 이미 떠
있는 인스턴스에 반영하려면 SSM으로 `/opt/soar/scripts/*`와 `/opt/soar/.env`를
직접 갱신하고 `systemctl restart soar-response-api.service`해야 한다. `.env`를
`echo ... >> .env`로 갱신할 때 CRLF가 섞이면(Windows에서 작업했을 때 흔함)
스크립트가 `line N: $'\r': command not found`로 깨진다 — `sed -i 's/\r$//' .env`로
정리할 것.

**등급 정책(레벨 기준):** critical(15~16) = 완전자동, high(12~14) = 승인 후 자동.
세션 revoke 액션 자체는 아래 두 브랜치가 동일한 `/respond/session-revoke` 호출을
공유하고, 차이는 승인 노드가 있고 없고뿐이다.

### 6-2. rule 100013/100033 브랜치 — 세션 revoke (high, 사람 승인 필수, 미구현)

탈취되는 건 IAM 액세스키가 아니라 EC2 인스턴스 프로필의 **STS 임시 세션**이라
`iam:UpdateAccessKey`는 안 먹힌다. 유효한 방법은 `aws:TokenIssueTime` 조건부
Deny-all 인라인 정책을 role에 붙여서 이미 발급된 세션을 강제 무효화하는 것
(AWS 콘솔의 "Revoke active sessions" 버튼과 동일한 메커니즘, `respond-session-revoke.sh`
가 이미 구현돼있음 — 6-3 참고).

100013(level 14, IMDS 자격증명 경로 조회 시도 — 200 확증 전)과 100033(level 13,
SSE-C 키로 문서 조회/반출 정황 — 단독 발화)은 둘 다 high 등급이라 승인을 거쳐야
한다. **이 브랜치는 아직 Shuffle에 안 만들어져 있다** — 이 Shuffle 버전의 앱
카탈로그(Shuffle Tools 1.2.0, 액션 53개 전수 확인)에 승인 대기용 "User Input"
액션이 없어서, 확실한 방법을 찾기 전까지 보류했다. `soar-response-api.py`의
`/respond/session-revoke` 라우트는 이미 100013/100033을 허용 목록에 포함해뒀으므로,
승인 메커니즘만 찾으면 API 재배포 없이 바로 연결 가능하다.

승인 노드를 못 찾으면 대안:
1. Shuffle GUI Triggers 패널의 4번째 아이콘(커서 모양)이 User Input일 가능성 있음 — 확인 필요
2. 안 되면 100013/100033은 알림만(Discord) 보내고, 세션 revoke는 사람이 알림 보고
   수동으로 `respond-session-revoke.sh`를 SSM으로 실행하는 방식으로 남겨둔다
   (오히려 이쪽이 검증 안 된 승인 흉내보다 안전하다).

브랜치를 만들 땐 6-3의 `Session_Revoke_Auto`처럼 `Change_Me` -> (승인 노드) ->
같은 로컬 API 호출을 붙이되, Filter 조건은 6-1과 같은 이유로 `is`/`in`이 아니라
`contains`, 그리고 100013/100033 각각 별도 브랜치로 만들 것.

### 6-3. rule 100014/100034 브랜치 — 세션 revoke (critical, 완전자동, 구현 완료)

100014(level 15, HTTP 200 응답으로 IMDS 자격증명 탈취 확증)와 100034(level 15,
재암호화→lifecycle→반출 전 단계 상관분석 확증)는 둘 다 critical 등급이라 승인 없이
자동 실행한다. 100014는 상관분석 없이 단일 요청/응답만으로 뜨는 룰이지만, 매칭
조건(메타데이터 IP + 알려진 취약 엔드포인트 + IMDS 자격증명 경로 + 200 응답)이
전부 겹쳐야 하므로 정상 트래픽에서 나올 조합이 아니다 — 100034와 마찬가지로
승인 게이트로 지연시킬 만한 불확실성이 없다고 본다.

**Shuffle에 실제로 구현된 노드/브랜치** (`Session_Revoke_Auto` 액션):

1. `Change_Me` 뒤에 `Session_Revoke_Auto`(Http POST) 노드, 대상
   `http://<shuffle 사설IP>:8088/respond/session-revoke`.
2. 6-1과 동일하게 `$exec.rule.id contains 100014`, `$exec.rule.id contains 100034`
   각각 별도 브랜치로 연결(`is`/`in`은 이 Shuffle 버전에서 매치 안 됨).
3. `respond-session-revoke.sh`가 앱 EC2 role에 `TokenIssueTime` 조건부 Deny-all
   인라인 정책(`shuffle-emergency-revoke`)을 부착한다.

**주의(실제로 겪음):** 세션 revoke는 앱 EC2가 쓰는 STS 세션 전체를 막으므로, 테스트로
한 번 발화시켰다가 실제로 병원 예약 앱이 마비된 걸 확인했다. 테스트/실습 후에는
반드시 정리할 것:
```bash
aws iam delete-role-policy --role-name vuln-hospital-ec2-ssm-role --policy-name shuffle-emergency-revoke
```
"critical = 완전자동"이라는 등급 정책을 일관되게 적용한 결과이며, 이 트레이드오프
(가용성 vs 즉시 차단)는 운영 전 인지하고 있을 것.

### 6-4. 알림(Discord) 설정

Discord 알림은 이미 인프라에 배선돼 있다 — `terraform.tfvars`에 `discord_webhook_url`
값을 채워 넣으면 `bootstrap-import.sh`가 배포 시 워크플로 JSON의 Discord 노드
`url` 파라미터에 자동 주입한다([modules/shuffle/variables.tf:56](../vuln-hospital-booking-infra/modules/shuffle/variables.tf#L56)).
**아직 tfvars에 이 값이 없으면 알림이 전혀 안 나간다** — Discord 서버에서
채널 설정 -> 연동 -> 웹훅 만들기로 URL을 받아서 채워넣을 것.

각 브랜치(일반/100031/100014) 끝에 별도 Discord 노드를 하나씩 연결하고, 메시지
바디에 브랜치를 구분할 수 있는 문구(예: "🔧 자동조치: lifecycle 원복 완료",
"⏸️ 승인 대기: 세션 revoke 필요")를 넣으면 운영자가 채팅만 보고도 무슨 상황인지
바로 알 수 있다.

### 6-5. 아직 안 된 것 — SSH 침해 체인(100170~100183)

위는 SSRF -> SSE-C 랜섬웨어 체인 전용이다. 유출 SSH 키 침해 체인(로컬 룰
`vuln_hospital_ssh_compromise.xml`)은 아직 알림 분기조차 없다 — 나중에 붙일 때는
`100172`/`100173`(FIM 확증)이나 `100179`/`100180`(체인 확증) 발화 시 EC2를 격리
보안그룹으로 옮기는 `ec2:ModifyInstanceAttribute` 액션을 추가하는 식으로, 위와
같은 패턴(권한은 Terraform에 최소 범위로, 워크플로는 GUI에서 Filter+승인 노드로)을
따르면 된다. 이때 `shuffle_ec2` role에 `ec2:ModifyInstanceAttribute`/
`ec2:DescribeInstances`(대상 인스턴스 조회용) 권한 추가가 필요하다.
