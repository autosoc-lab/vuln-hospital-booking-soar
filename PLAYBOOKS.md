# SOAR 플레이북 설계

Shuffle 워크플로는 GUI에서 드래그앤드롭으로 만드는 게 정상 경로라, 이 문서는 "임포트하면
끝나는 JSON"이 아니라 **무엇을, 왜, 어떤 조건으로** 만들어야 하는지를 정리한 설계 문서다.
Shuffle이 뜬 뒤(README.md 참고) 이 문서를 보면서 워크플로 하나를 만들면 된다.

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
            Slack/이메일 알림   케이스 생성      (2단계) AWS 자동조치
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
| `ssrf,credential_access,critical` (100013/100014) | 14~15 | IMDS 자격증명 탈취 (100014=200 응답으로 확증) | 앱 로그 | **케이스 생성 + 긴급 알림 + 사람 승인 후 세션 revoke** (2단계 구현됨, [6-2](#6-2-rule-100014-브랜치--세션-revoke-사람-승인-필수) 참고) |
| `s3_exfil` (100021) | 12 | 문서 버킷 대량 다운로드(sync 유출 의심) | CloudTrail(S3 데이터 이벤트) | 케이스 생성 + 알림 |
| `s3_ransomware` (100030/100031) | 10~12 | SSE-C 재암호화 / lifecycle 자동삭제 설정 (Codefinger 패턴) | CloudTrail | 100030: 케이스 생성 + 긴급 알림 / **100031: 완전자동 lifecycle 원복** (2단계 구현됨, [6-1](#6-1-rule-100031-브랜치--lifecycle-원복-완전자동-승인-불필요) 참고) |
| `s3_ransomware,attack_scenario,critical` (100032) | 15 | 같은 버킷에서 SSE-C 재암호화 직후 lifecycle 변경 - 상관분석 확증 (정상 운영으로는 안 나오는 조합) | CloudTrail | **완전자동 lifecycle 원복 + 긴급 알림** — 100031과 동일 조치, [6-1](#6-1-rule-100031-브랜치--lifecycle-원복-완전자동-승인-불필요) 참고 (같은 로그가 100031 대신 100032로 발화하므로 Filter가 둘 다 잡아야 함) |
| `log_tampering` (100040~100045) | 9~12 | CloudTrail/Flow Logs 중지·삭제·정책변경 | CloudTrail | **케이스 생성 + Slack 긴급 알림** (방어회피 = 이미 침해 진행 중일 가능성 높음) |
| `vpcflow,recon` (100052) | 10 | 포트스캔/정찰 의심 | VPC Flow Logs | Slack 알림 |
| `vpcflow,exfil` (100054) | 10 | 대용량 외부 반출 의심 | VPC Flow Logs | 케이스 생성 + Slack |
| `ssh_compromise,*` (100170~100183) | 5~15 | 유출 SSH키 침해 -> 정찰 -> 권한상승 -> 데이터반출 체인 | auditd(agent) | 레벨 12 이상만 케이스 생성, 그 미만은 로그만 |
| `attack_scenario,privilege_escalation,critical` (100179/100180) | 15 | 권한상승 확증 (체인 상관분석 룰) | auditd | **케이스 생성 + Slack 긴급 알림** |
| `aws`, `guardduty` (Wazuh 기본 룰셋) | 룰마다 다름 | GuardDuty finding (정찰/자격증명침해/C2/크립토재킹 등) | GuardDuty -> S3 | 레벨 기준으로 Slack 알림 |

레벨 임계값은 `enable-shuffle-integration.sh` 실행 시 두 번째 인자로 조절 가능
(기본 6). 처음엔 6으로 넓게 받고, 알림이 너무 많으면 8~10으로 올리는 걸 권장.

## 3. "Wazuh Alert Router" 워크플로 만들기

1. Shuffle UI(`http://<shuffle-ip>:3001`) 로그인 -> **Workflows -> New Workflow**,
   이름을 `Wazuh Alert Router`로 지정.
2. 좌측 트리거 목록에서 **Webhook**을 캔버스로 드래그. 트리거를 클릭하면 URL이
   `http://<shuffle-ip>:3001/api/v1/hooks/webhook_XXXXXXXX` 형태로 생성됨 — 이 URL을
   복사해둔다 (다음 단계에서 Wazuh 쪽에 등록할 값).
3. Webhook 노드 뒤에 **Shuffle Tools** 앱의 **"Filter"** 액션을 연결해서 분기 조건을
   만든다. Filter의 조건식에서 다음 필드를 참조할 수 있다 (Wazuh alert JSON 그대로 들어옴):
   - `$exec.rule.level` — 정수 레벨
   - `$exec.rule.groups` — 배열, 예: `["ssrf","credential_access","critical"]`
   - `$exec.rule.description`, `$exec.rule.id`
   - `$exec.agent.name` — 어느 EC2에서 왔는지 (app / wazuh 자체 등)
4. 분기별로 브랜치를 나눠서:
   - **일반 알림 브랜치** (`rule.level < 12`): Shuffle Tools의 **"Send Slack message"**
     (또는 Email) 액션 하나만 연결. 메시지 바디에 `$exec.rule.description`,
     `$exec.rule.level`, `$exec.agent.name`, `$exec.full_log`를 넣는다.
   - **긴급 브랜치** (`rule.level >= 12` 이거나 `rule.groups`에 `critical` 포함):
     Slack/Email 알림 + (선택) Shuffle의 **Cases** 앱으로 케이스 생성. 케이스 제목에
     `$exec.rule.description`, 우선순위는 `rule.level`에 따라 매핑.
5. 저장 후 **우측 상단 토글로 워크플로를 Enable**. (Disable 상태면 웹훅이 와도 실행 안 됨)

## 4. Wazuh 쪽에 웹훅 등록

Shuffle에서 복사한 webhook URL을 wazuh 매니저 EC2에 SSH로 접속해서 등록한다
(스크립트는 terraform이 이미 배포해뒀음):

```bash
ssh -i ssh/vuln-hospital-lab.pem ubuntu@<wazuh_manager_public_ip>
sudo /opt/soar-integration/enable-shuffle-integration.sh \
  'http://<shuffle-ip>:3001/api/v1/hooks/webhook_XXXXXXXX' 6
```

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
  -d '{"rule":{"level":14,"id":"100014","groups":["ssrf","credential_access","critical"],"description":"SSRF -> EC2 IMDS credential theft CONFIRMED"},"agent":{"name":"app-ec2"}}'
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

100013(level 14, SSRF→IMDS 조회 시도 — 200 확증 전 단계)이나 SSH 침해 체인의
level 14/15 룰들(`100172`~`100180`)은 기준상으로는 자동조치 대상이지만, 아직
구체적인 조치가 설계/구현되지 않아 **지금은 1단계(알림만)로 남겨둔다.** 나중에
붙일 때는 6-4를 참고.

`modules/shuffle/main.tf`의 `shuffle_ec2` role에는 이미 아래 두 조치에 필요한
최소 권한이 붙어있다(둘 다 리소스를 특정 ARN 하나로 좁혀놓음 — 계정 전체가 아니라
documents 버킷/app EC2 role 딱 그거 하나만 건드릴 수 있음):

| Terraform 리소스 | 부여 액션 | 대상 |
|---|---|---|
| `aws_iam_role_policy.shuffle_lifecycle_revert` | `s3:GetLifecycleConfiguration`, `s3:PutLifecycleConfiguration` | documents 버킷 ARN |
| `aws_iam_role_policy.shuffle_revoke_session` | `iam:PutRolePolicy`, `iam:DeleteRolePolicy`, `iam:GetRolePolicy` | 앱 EC2 role(`ec2_ssm`) ARN |

Shuffle 앱 목록에서 **AWS** 앱을 인증 설정할 때는 별도 자격증명 없이 Shuffle EC2의
인스턴스 프로파일을 그대로 쓰면 된다(위 정책이 이미 그 role에 붙어있으므로).

### 6-1. rule 100031/100032 브랜치 — lifecycle 원복 (완전자동, 승인 불필요)

되돌리기 쉽고 부작용이 거의 없는 조치라 사람 승인 없이 자동화한다. documents 버킷은
versioning은 켜져 있지만 MFA Delete/Object Lock이 없어서([modules/app/main.tf:150](../vuln-hospital-booking-infra/modules/app/main.tf#L150)
참고), 이 lifecycle 룰이 실제로 실행되기 전(보통 며칠의 유예)이 복구 가능 여부가 걸린
골든타임이다 — 그래서 자동화 우선순위가 가장 높다.

1. Webhook 뒤에 **Filter** 노드 추가, 조건: `$exec.rule.id` `is` `100031` **OR**
   `$exec.rule.id` `is` `100032`. 둘 다 잡아야 하는 이유: 상관분석 조건(같은
   버킷에서 직전에 100030이 떴는지)이 충족되면 그 로그는 100031이 아니라
   **100032로 발화**하기 때문에(같은 트리에서 더 깊은 룰이 우선 — [local_rules.xml:116](../vuln-hospital-booking-infra/modules/wazuh/files/local_rules.xml#L116)
   참고), 100031만 필터링하면 확증된(더 위험한) 케이스를 오히려 놓친다.
2. 그 뒤에 **AWS** 앱의 S3 관련 액션(`get_bucket_lifecycle_configuration` 등 정확한
   액션명은 Shuffle AWS 앱 버전마다 다르니 앱 상세에서 확인) 두 개를 순서대로:
   - 먼저 `put_bucket_lifecycle_configuration`을 **빈 규칙 목록**(`{"Rules": []}`)으로
     호출해 방금 추가된 악성 lifecycle을 제거. 버킷명은 `documents_bucket_name`
     terraform output 값을 그대로 하드코딩(랩 환경이라 버킷이 재생성되지 않는 한 고정).
   - Shuffle의 범용 "AWS" 앱에 해당 액션이 없으면, Shuffle Tools의 HTTP 액션으로는
     SigV4 서명이 안 되므로 대신 **AWS 앱의 Python 코드 실행 액션**(있는 버전이라면)이나
     간단한 boto3 스크립트를 쓰는 게 안전하다.
3. 실행 결과를 아래 6-3 알림 노드로 연결하되, **`$exec.rule.id`로 메시지를 구분**한다:
   - 100031: "🔧 자동조치: lifecycle 원복 완료 (미확증 — 정상 운영 변경일 수 있음, 확인 권장)"
   - 100032: "🚨 자동조치: lifecycle 원복 완료 (SSE-C 재암호화와 상관분석으로 확증된 랜섬웨어 체인)"

**배포 시 주의:** `local_rules.xml`은 Wazuh 매니저가 **최초 부팅 시에만** S3에서
받아온다([modules/wazuh/main.tf](../vuln-hospital-booking-infra/modules/wazuh/main.tf) 참고).
이미 떠 있는 인스턴스는 `terraform apply`로 S3 오브젝트만 갱신해도 룰이 자동
반영되지 않는다 — Session Manager로 접속해서 아래를 수동으로 실행해야 100032가
실제로 발화한다:
```bash
sudo aws s3 cp "s3://<log_bucket_name>/wazuh-rules/local_rules.xml" /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

### 6-2. rule 100014 브랜치 — 세션 revoke (사람 승인 필수)

탈취되는 건 IAM 액세스키가 아니라 EC2 인스턴스 프로필의 **STS 임시 세션**이라
`iam:UpdateAccessKey`는 안 먹힌다. 유효한 방법은 `aws:TokenIssueTime` 조건부
Deny-all 인라인 정책을 role에 붙여서 이미 발급된 세션을 강제 무효화하는 것
(AWS 콘솔의 "Revoke active sessions" 버튼과 동일한 메커니즘). 서비스 중단을
유발할 수 있는 조치라 **반드시 사람 승인을 거친다.**

1. Webhook 뒤에 **Filter** 노드, 조건: `$exec.rule.id` `is` `100014`
2. **User Input** 노드 연결 — 메시지에 `$exec.rule.description`, `$exec.agent.name`,
   `$exec.data.full_log`(원본 요청 정보)를 넣어서 승인자가 판단할 근거를 준다.
   승인/거부 두 갈래로 분기 가능하게 설정.
3. 승인 갈래 뒤에 **AWS** 앱의 `put_role_policy` 액션:
   - `RoleName`: `app_ec2_role_name` terraform output 값 (예: `vuln-hospital-ec2-ssm-role`)
   - `PolicyName`: 예) `shuffle-emergency-revoke`
   - `PolicyDocument`:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": "*",
         "Resource": "*",
         "Condition": {
           "DateLessThan": {"aws:TokenIssueTime": "<이 워크플로 실행 시각, ISO8601>"}
         }
       }]
     }
     ```
     `TokenIssueTime` 값은 워크플로 실행 시점(`$exec.execution_argument` 또는 Shuffle의
     현재시각 함수)으로 채워야 한다 — 너무 과거로 잡으면 정상 세션까지 막히고, 너무
     미래로 잡으면 공격자 세션이 안 막힌다.
   - 거부/타임아웃 갈래는 "조치 보류, 수동 확인 필요" 알림만 보내고 종료.
4. 사고 종료 후에는 `iam:DeleteRolePolicy`로 이 revoke 정책을 제거해야 앱 EC2가
   정상 동작한다 — 별도 "복구" 워크플로나 수동 단계로 관리할 것.

### 6-3. 알림(Discord) 설정

Discord 알림은 이미 인프라에 배선돼 있다 — `terraform.tfvars`에 `discord_webhook_url`
값을 채워 넣으면 `bootstrap-import.sh`가 배포 시 워크플로 JSON의 Discord 노드
`url` 파라미터에 자동 주입한다([modules/shuffle/variables.tf:56](../vuln-hospital-booking-infra/modules/shuffle/variables.tf#L56)).
**아직 tfvars에 이 값이 없으면 알림이 전혀 안 나간다** — Discord 서버에서
채널 설정 -> 연동 -> 웹훅 만들기로 URL을 받아서 채워넣을 것.

각 브랜치(일반/100031/100014) 끝에 별도 Discord 노드를 하나씩 연결하고, 메시지
바디에 브랜치를 구분할 수 있는 문구(예: "🔧 자동조치: lifecycle 원복 완료",
"⏸️ 승인 대기: 세션 revoke 필요")를 넣으면 운영자가 채팅만 보고도 무슨 상황인지
바로 알 수 있다.

### 6-4. 아직 안 된 것 — SSH 침해 체인(100170~100183)

위는 SSRF -> SSE-C 랜섬웨어 체인 전용이다. 유출 SSH 키 침해 체인(로컬 룰
`vuln_hospital_ssh_compromise.xml`)은 아직 알림 분기조차 없다 — 나중에 붙일 때는
`100172`/`100173`(FIM 확증)이나 `100179`/`100180`(체인 확증) 발화 시 EC2를 격리
보안그룹으로 옮기는 `ec2:ModifyInstanceAttribute` 액션을 추가하는 식으로, 위와
같은 패턴(권한은 Terraform에 최소 범위로, 워크플로는 GUI에서 Filter+승인 노드로)을
따르면 된다. 이때 `shuffle_ec2` role에 `ec2:ModifyInstanceAttribute`/
`ec2:DescribeInstances`(대상 인스턴스 조회용) 권한 추가가 필요하다.
