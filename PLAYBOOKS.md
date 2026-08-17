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

Terraform apply 후 Shuffle EC2에는 `soar-response-api.service`가 함께 배포된다. Wazuh
integration은 `level >= 15`인 SSH 침해 확증 룰만 이 API로 전달하고, API가 다음 헬퍼를
실행한다.

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

## 6. 적용 명령

인프라 저장소에서:

```bash
terraform init
terraform plan -var-file="terraform.tfvars"
terraform apply -var-file="terraform.tfvars"
```

적용 후 확인:

```bash
terraform output shuffle_dashboard_url
terraform output wazuh_dashboard_url
```

Shuffle UI에서 `Wazuh Alert Router`가 import되어 있고 Webhook이 Running이면 정상이다.
