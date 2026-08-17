# vuln-hospital-booking-soar

`vuln-hospital-booking` 랩의 SOAR(보안 오케스트레이션/자동대응) 계층. [Shuffle](https://github.com/Shuffle/Shuffle)
(오픈소스, self-host)을 배포하고, 이미 구축된 Wazuh SIEM(호스트 이벤트 + CloudTrail/
GuardDuty/VPC Flow Logs)의 알림을 받아 대응 워크플로를 실행한다.

왜 오픈소스 self-host인가: 이 랩의 Wazuh도 AWS Marketplace AMI가 아니라 EC2 위에
직접 설치되어 있고, 커스텀 룰/디코더를 자유롭게 얹는 구조다. Shuffle도 같은 패턴을
따르는 게 일관적이고, PoC/실습 단계에서는 비용도 self-host 쪽이 유리하다.

## 아키텍처

- Wazuh 매니저(EC2, `vuln-hospital-booking-infra`의 `modules/wazuh`)가 호스트 이벤트와
  AWS 로그(CloudTrail/GuardDuty/VPC Flow Logs, `wodle aws-s3`로 수집)를 모두 룰 매칭한다.
- 이 저장소는 Shuffle 자체(backend/frontend/orborus/opensearch)를 별도 EC2
  (`modules/shuffle`)에 docker compose로 띄운다.
- Wazuh가 레벨 임계값을 넘는 알림을 **custom-shuffle** integration으로 Shuffle 웹훅에
  POST하면, Shuffle 워크플로가 룰 그룹/레벨을 보고 알림·케이스 생성 등을 실행한다.
- 자세한 라우팅 규칙과 워크플로 만드는 법은 [PLAYBOOKS.md](PLAYBOOKS.md) 참고.

## 배포

### 옵션 A — Terraform으로 EC2에 배포 (권장, 랩 전체와 통합됨)

`vuln-hospital-booking-infra` 루트에서:

```bash
# terraform.tfvars에 아래 값 추가
# soar_git_ref                = "main"                # 이 레포에서 clone할 브랜치
# shuffle_admin_username      = "admin"
# shuffle_admin_password      = "<8자 이상>"
# shuffle_encryption_modifier = "<openssl rand -hex 32 결과>"
# shuffle_opensearch_password = "<대소문자/숫자/특수문자 포함 8자+>"

terraform apply
```

`shuffle_dashboard_url` output으로 UI 주소가 나온다. EC2 user_data가 이 레포를
clone -> `.env` 생성 -> `docker compose up -d` -> `workflows/*.json` 자동 import ->
고정 Webhook start까지 처리한다. Wazuh도 같은 고정 hook id로 integration을 자동 등록하므로
별도 SSH 수동 연결 없이 `terraform apply` 후 알림이 Shuffle로 들어간다.

> t3.medium(4GB) 인스턴스라 상시 켜두면 과금된다. 실습 종료 시
> `terraform destroy`(또는 shuffle 모듈만 `terraform destroy -target=module.shuffle`)로 정리할 것.

### 옵션 B — 로컬 Docker로 먼저 구조 확인

```bash
git clone https://github.com/autosoc-lab/vuln-hospital-booking-soar
cd vuln-hospital-booking-soar
cp .env.example .env
# .env 에서 SHUFFLE_ENCRYPTION_MODIFIER / SHUFFLE_OPENSEARCH_PASSWORD 등 채우기
mkdir -p shuffle-apps shuffle-files shuffle-database
docker compose up -d
```

`http://localhost:3001` 접속. 다만 이 경우 AWS 위 Wazuh 매니저가 로컬 PC로 웹훅을
쏘려면 포트포워딩/터널링(ngrok 등)이 필요하니, Wazuh 연동까지 테스트하려면 옵션 A를
권장한다.

## Wazuh 연동

`vuln-hospital-booking-infra`의 `modules/wazuh`가 다음을 EC2에 배포하고 부팅 시 자동으로
활성화한다:

- `/var/ossec/integrations/custom-shuffle` (+ `.py`) — Wazuh 알림을 Shuffle 웹훅으로
  그대로 POST하는 커스텀 integration.
- `/opt/soar-integration/enable-shuffle-integration.sh` — 실제 `<integration>` 블록을
  `ossec.conf`에 넣고 `wazuh-manager`를 재시작하는 헬퍼.

Webhook hook id는 `bootstrap-import.sh`와 infra `modules/wazuh/variables.tf`에 같은 값으로
고정되어 있다. 워크플로 JSON에서 Webhook 트리거를 새로 만들면 두 값을 함께 갱신해야 한다.

## AWS 로그 대응 범위

별도로 AWS를 다시 붙일 필요 없음 — CloudTrail/GuardDuty/VPC Flow Logs는 이미 Wazuh
매니저의 `wodle aws-s3`가 읽어서 룰 매칭까지 끝낸 뒤 같은 웹훅으로 Shuffle에 들어온다.
즉 "호스트 이벤트"와 "AWS 로그 이벤트"가 Shuffle 입장에선 동일한 하나의 웹훅/JSON
포맷으로 도착하고, `rule.groups`/`rule.level`로 구분해서 분기하면 된다. 구체적으로
어떤 AWS 관련 룰(S3 유출, SSE-C 랜섬웨어, 로그변조, VPC 포트스캔/대량반출, GuardDuty
finding)이 잡히는지는 PLAYBOOKS.md의 라우팅 테이블 참고.

## 자동 대응 범위

infra의 `modules/shuffle`은 Shuffle EC2 instance profile에 다음 최소 권한을 부여한다.

- 앱 EC2 한 대에 대한 `ec2:ModifyInstanceAttribute`, `ec2:CreateTags`
- 실습용 유출 IAM 사용자 한 명에 대한 `iam:ListAccessKeys`, `iam:UpdateAccessKey`
- 문서 버킷 영향도 확인용 `s3:Get*`, `s3:ListBucket`, `cloudtrail:LookupEvents`

호스트에서 즉시 실행 가능한 대응 헬퍼는 `scripts/respond-ssh-compromise.sh`다. Terraform은
같은 EC2에 `scripts/soar-response-api.py`를 systemd 서비스로 띄운다. 자동 조치는 Shuffle
GUI의 `Wazuh Alert Router` 워크플로 안에 있는 `SOAR_Response_API` 노드가 내부 API를
호출하면서 실행된다. 따라서 워크플로 Executions 화면에서 Discord 알림과 SOAR API 호출
단계를 함께 확인할 수 있다.
수동 재실행이 필요하면 Shuffle EC2에서 아래처럼 실행할 수 있다.

```bash
sudo /opt/soar/scripts/respond-ssh-compromise.sh
```
