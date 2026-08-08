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
| `ssrf,credential_access,critical` (100013/100014) | 14~15 | IMDS 자격증명 탈취 (100014=200 응답으로 확증) | 앱 로그 | **케이스 생성 + Slack 긴급 알림** (2단계에서: 탈취된 role의 access key 자동 비활성화) |
| `s3_exfil` (100021) | 12 | 문서 버킷 대량 다운로드(sync 유출 의심) | CloudTrail(S3 데이터 이벤트) | 케이스 생성 + Slack |
| `s3_ransomware` (100030/100031) | 10~12 | SSE-C 재암호화 / lifecycle 자동삭제 설정 (Codefinger 패턴) | CloudTrail | **케이스 생성 + Slack 긴급 알림** |
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

## 6. 다음 단계 (2단계: AWS 자동조치로 확장할 때)

1단계는 알림/케이스 생성까지만 한다. 실제 AWS API 조치(예: 유출된 IAM 액세스 키
`iam:UpdateAccessKey`로 비활성화, 침해 의심 EC2를 격리 보안그룹으로
`ec2:ModifyInstanceAttribute`)를 추가하려면:

1. `modules/shuffle/main.tf`의 `aws_iam_role.shuffle_ec2`에 필요한 최소 권한 정책을
   추가 (예: 특정 IAM 사용자 ARN 한정 `iam:UpdateAccessKey`).
2. Shuffle 앱 목록에서 **AWS** 앱을 인증 설정 (Shuffle EC2의 인스턴스 프로파일을
   쓰거나, 별도 자격증명을 앱에 등록).
3. 워크플로의 긴급 브랜치 뒤에 AWS 액션 노드를 추가하고, 실행 전 **사람 승인 단계**
   (Shuffle의 "User Input" 노드)를 하나 끼워 넣는 걸 강력 권장 — 랩이라도 오탐으로
   실제 자원을 건드리면 실습이 끊긴다.
