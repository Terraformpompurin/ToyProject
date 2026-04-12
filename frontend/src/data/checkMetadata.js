/**
 * 커스텀 Checkov 체크의 ISMS-P 매핑 및 보안 메타데이터.
 * Python checks/ 디렉터리의 METADATA와 1:1 대응.
 */
export const CHECK_METADATA = {
  // ── Security Group ──────────────────────────────────────
  CKV_CUSTOM_SG_1: {
    severity: 'HIGH',
    service: 'Security Group',
    ismsP: '2.6.1',
    title: 'Security Group 인바운드 전체 IP 개방',
    reason:
      '0.0.0.0/0 또는 ::/0 허용 시 인터넷 전체에서 해당 포트로 접근 가능해져 ' +
      '무차별 대입 공격, 포트 스캔, 악성 트래픽에 노출됩니다.',
    before: `ingress {
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # 위험: 전체 허용
}`,
    after: `ingress {
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # 내부 IP 대역만 허용
}`,
    incident: 'Capital One(2019): 과도하게 개방된 Security Group이 초기 침투 경로가 됨',
  },

  CKV_CUSTOM_SG_2: {
    severity: 'CRITICAL',
    service: 'Security Group',
    ismsP: '2.6.1',
    title: 'Security Group SSH(22) 전체 개방',
    reason:
      'SSH 포트를 인터넷 전체에 개방하면 브루트포스 공격, 크리덴셜 스터핑 등에 ' +
      '서버가 직접 노출됩니다. Shodan 등 스캐너가 수초 내에 탐지합니다.',
    before: `ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # 위험: SSH 전체 공개
}`,
    after: `ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["203.0.113.10/32"]  # 관리자 IP만 허용
}`,
    incident: 'Capital One(2019): EC2 SSH 22번 포트 전체 개방이 공격 진입점으로 활용됨',
  },

  CKV_CUSTOM_SG_3: {
    severity: 'CRITICAL',
    service: 'Security Group',
    ismsP: '2.6.1',
    title: 'Security Group 전 포트 개방',
    reason:
      'protocol = "-1"(All traffic) 사용 시 서비스에 필요하지 않은 모든 포트가 노출되어 ' +
      '공격 표면이 극대화됩니다.',
    before: `ingress {
  from_port   = 0
  to_port     = 0
  protocol    = "-1"       # 위험: 모든 트래픽 허용
  cidr_blocks = ["0.0.0.0/0"]
}`,
    after: `ingress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"      # 필요한 포트만 명시
  cidr_blocks = ["0.0.0.0/0"]
}`,
    incident: '광범위한 포트 개방은 Redis 6379, ES 9200 등 내부 서비스 포트 노출로 이어짐',
  },

  CKV_CUSTOM_SG_4: {
    severity: 'MEDIUM',
    service: 'Security Group',
    ismsP: '2.6.1',
    title: 'Security Group 이그레스 무제한 허용',
    reason:
      '아웃바운드 전체 허용 시 침해된 인스턴스에서 C2 서버 통신, 데이터 유출, ' +
      '횡적 이동이 자유롭게 이루어질 수 있습니다.',
    before: `egress {
  from_port   = 0
  to_port     = 0
  protocol    = "-1"       # 위험: 아웃바운드 전체 허용
  cidr_blocks = ["0.0.0.0/0"]
}`,
    after: `egress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"      # HTTPS 아웃바운드만 허용
  cidr_blocks = ["0.0.0.0/0"]
}`,
    incident: '아웃바운드 무제한 시 DNS tunneling, HTTPS exfiltration 가능',
  },

  CKV_CUSTOM_SG_5: {
    severity: 'CRITICAL',
    service: 'Security Group',
    ismsP: '2.6.1',
    title: 'Security Group RDP(3389) 전체 개방',
    reason:
      'RDP 포트를 인터넷에 개방하면 BlueKeep(CVE-2019-0708) 등 ' +
      '원격 코드 실행 취약점 및 무차별 대입 공격에 즉시 노출됩니다.',
    before: `ingress {
  from_port   = 3389
  to_port     = 3389
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # 위험: RDP 전체 공개
}`,
    after: `ingress {
  from_port   = 3389
  to_port     = 3389
  protocol    = "tcp"
  cidr_blocks = ["203.0.113.10/32"]  # 관리자 IP만
}`,
    incident: '랜섬웨어 초기 침투의 60% 이상이 인터넷에 노출된 RDP를 통해 발생(Coveware 2023)',
  },

  // ── S3 ──────────────────────────────────────────────────
  CKV_CUSTOM_S3_1: {
    severity: 'CRITICAL',
    service: 'S3',
    ismsP: '2.6.2',
    title: 'S3 버킷 퍼블릭 ACL 설정',
    reason:
      'acl = "public-read" 설정 시 버킷 내 모든 객체가 인터넷에 공개됩니다. ' +
      '개인정보·기밀 데이터 노출로 직결됩니다.',
    before: `resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"  # 위험: 전체 공개
}`,
    after: `resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "private"      # 기본값을 항상 private으로
}`,
    incident: 'Toyota(2023): S3 퍼블릭 버킷으로 215만 명 고객 데이터 8년간 노출',
  },

  CKV_CUSTOM_S3_2: {
    severity: 'HIGH',
    service: 'S3',
    ismsP: '2.6.2',
    title: 'S3 Public Access Block 미적용',
    reason:
      '4개 플래그가 모두 true여야 ACL·버킷정책을 통한 퍼블릭 접근을 계정 수준에서 차단할 수 있습니다.',
    before: `# aws_s3_bucket_public_access_block 리소스 없음
# 또는:
resource "aws_s3_bucket_public_access_block" "example" {
  block_public_acls   = false  # 위험
  block_public_policy = false  # 위험
}`,
    after: `resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = aws_s3_bucket.example.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
    incident: 'Toyota(2023): Public Access Block 미설정이 데이터 유출의 직접 원인',
  },

  CKV_CUSTOM_S3_3: {
    severity: 'HIGH',
    service: 'S3',
    ismsP: '2.7.1',
    title: 'S3 버킷 서버 사이드 암호화 미적용',
    reason:
      'SSE가 없으면 저장된 객체가 평문으로 보관되어, 스토리지 침해 시 데이터가 즉시 노출됩니다.',
    before: `resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  # server_side_encryption_configuration 없음
}`,
    after: `resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}`,
    incident: '암호화되지 않은 S3는 스냅샷 탈취 시 평문 데이터 즉각 노출',
  },

  CKV_CUSTOM_S3_4: {
    severity: 'MEDIUM',
    service: 'S3',
    ismsP: '2.9.1',
    title: 'S3 버킷 버전 관리 미설정',
    reason:
      '버전 관리 비활성화 시 실수로 삭제·덮어쓴 객체를 복구할 수 없고, ' +
      '랜섬웨어로 암호화된 파일을 이전 버전으로 복원하는 것도 불가능합니다.',
    before: `resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  # versioning 블록 없음
}`,
    after: `resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Enabled"
  }
}`,
    incident: '랜섬웨어 피해 기업 중 S3 버전관리 미설정으로 복구 불가 사례 다수',
  },

  // ── IAM ─────────────────────────────────────────────────
  CKV_CUSTOM_IAM_1: {
    severity: 'CRITICAL',
    service: 'IAM',
    ismsP: '2.5.1',
    title: 'IAM 정책 와일드카드(*) 사용',
    reason:
      'Action = "*" + Resource = "*" 조합은 사실상 관리자 권한을 부여합니다. ' +
      '침해 시 공격자가 AWS 계정 전체를 장악할 수 있습니다.',
    before: `resource "aws_iam_policy" "example" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["*"]      # 위험: 모든 액션 허용
      Resource = ["*"]      # 위험: 모든 리소스
    }]
  })
}`,
    after: `resource "aws_iam_policy" "example" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = ["arn:aws:s3:::my-bucket/*"]
    }]
  })
}`,
    incident: 'Capital One(2019): IAM 와일드카드 권한 → S3 전체 접근 → 1억 건 데이터 유출',
  },

  CKV_CUSTOM_IAM_2: {
    severity: 'MEDIUM',
    service: 'IAM',
    ismsP: '2.5.1',
    title: 'IAM User에 정책 직접 연결',
    reason:
      'User에 정책을 직접 연결하면 권한 관리가 파편화되어 변경·감사가 어려워지고, ' +
      '퇴직자 정리 누락 위험이 높아집니다.',
    before: `resource "aws_iam_user_policy" "example" {
  name   = "my-policy"
  user   = aws_iam_user.example.name  # 위험: User 직접 연결
  policy = jsonencode({...})
}`,
    after: `# 그룹 기반 정책 관리로 전환
resource "aws_iam_group_policy" "example" {
  name   = "my-policy"
  group  = aws_iam_group.example.name
  policy = jsonencode({...})
}`,
    incident: 'User 직접 연결 정책은 감사 시 권한 추적 복잡도를 크게 높여 침해 탐지 지연',
  },

  CKV_CUSTOM_IAM_3: {
    severity: 'HIGH',
    service: 'IAM',
    ismsP: '2.5.2',
    title: 'Terraform으로 IAM Access Key 생성',
    reason:
      'IaC 코드로 Access Key를 생성하면 키 값이 tfstate 파일에 평문으로 저장됩니다.',
    before: `resource "aws_iam_access_key" "example" {
  user = aws_iam_user.example.name  # 위험: tfstate에 키 평문 저장
}`,
    after: `# aws_iam_access_key 리소스 삭제
# 대안: IAM Role + Instance Profile 사용
resource "aws_iam_instance_profile" "example" {
  name = "my-profile"
  role = aws_iam_role.example.name
}`,
    incident: 'tfstate S3 버킷 퍼블릭 노출 → Access Key 탈취 → 계정 탈취 사례 다수',
  },

  CKV_CUSTOM_IAM_4: {
    severity: 'HIGH',
    service: 'IAM',
    ismsP: '2.6.2',
    title: 'EC2 IMDSv2 미강제 (IMDSv1 허용)',
    reason:
      'http_tokens = "optional"(기본값)은 IMDSv1을 허용합니다. ' +
      'SSRF 취약점이 있는 앱에서 IMDSv1을 통해 IAM 자격증명을 탈취할 수 있습니다.',
    before: `resource "aws_instance" "example" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  # metadata_options 없음 → IMDSv1 허용
}`,
    after: `resource "aws_instance" "example" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 강제
    http_put_response_hop_limit = 1
  }
}`,
    incident: 'Capital One(2019): SSRF → IMDSv1 → IAM 자격증명 탈취 → S3 1억 건 유출',
  },

  // ── RDS ─────────────────────────────────────────────────
  CKV_CUSTOM_RDS_1: {
    severity: 'CRITICAL',
    service: 'RDS',
    ismsP: '2.6.1',
    title: 'RDS publicly_accessible = true',
    reason:
      'DB 인스턴스가 인터넷에 직접 노출되면 SQL 인젝션, 무차별 대입, ' +
      '알려진 DB 엔진 취약점 공격에 직접 노출됩니다.',
    before: `resource "aws_db_instance" "example" {
  publicly_accessible = true   # 위험: 인터넷 노출
  ...
}`,
    after: `resource "aws_db_instance" "example" {
  publicly_accessible = false  # VPC 내부에서만 접근
  db_subnet_group_name = aws_db_subnet_group.private.name
  ...
}`,
    incident: 'Toyota(2023): RDS publicly_accessible 설정이 DB 직접 노출 원인 중 하나',
  },

  CKV_CUSTOM_RDS_2: {
    severity: 'HIGH',
    service: 'RDS',
    ismsP: '2.7.1',
    title: 'RDS 스토리지 암호화 미적용',
    reason:
      'storage_encrypted = false이면 EBS 스냅샷·스토리지 침해 시 DB 데이터가 평문으로 노출됩니다.',
    before: `resource "aws_db_instance" "example" {
  storage_encrypted = false  # 위험: 평문 저장
  ...
}`,
    after: `resource "aws_db_instance" "example" {
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn  # CMK 사용 권장
  ...
}`,
    incident: '암호화되지 않은 RDS 스냅샷 공유 오류로 고객 데이터 유출 사례 보고',
  },

  CKV_CUSTOM_RDS_3: {
    severity: 'MEDIUM',
    service: 'RDS',
    ismsP: '2.9.1',
    title: 'RDS 백업 보존 기간 7일 미만',
    reason:
      'backup_retention_period = 0이면 자동 백업이 비활성화됩니다. ' +
      '랜섬웨어·실수 삭제 발생 시 복구가 불가능합니다.',
    before: `resource "aws_rds_cluster" "example" {
  backup_retention_period = 1   # 위험: 1일만 보관
  ...
}`,
    after: `resource "aws_rds_cluster" "example" {
  backup_retention_period = 7   # 최소 7일, 중요 DB는 30일 이상
  ...
}`,
    incident: '백업 미설정 상태에서 랜섬웨어 피해 → DB 완전 손실 사례 다수',
  },

  CKV_CUSTOM_RDS_4: {
    severity: 'MEDIUM',
    service: 'RDS',
    ismsP: '2.9.2',
    title: 'RDS Multi-AZ 미설정',
    reason:
      'Single-AZ RDS는 AZ 장애 발생 시 수십 분의 다운타임이 발생합니다. ' +
      'Multi-AZ는 자동 페일오버로 60~120초 내 복구를 보장합니다.',
    before: `resource "aws_db_instance" "example" {
  multi_az = false  # 위험: 단일 AZ
  ...
}`,
    after: `resource "aws_db_instance" "example" {
  multi_az = true   # 프로덕션 DB는 반드시 활성화
  ...
}`,
    incident: 'AZ 장애로 Single-AZ RDS 수십 분 다운 → 서비스 중단 사례',
  },

  CKV_CUSTOM_RDS_5: {
    severity: 'MEDIUM',
    service: 'RDS',
    ismsP: '2.9.1',
    title: 'RDS 삭제 보호 미활성',
    reason:
      'deletion_protection = false이면 terraform destroy 또는 콘솔 실수로 DB가 즉시 삭제됩니다.',
    before: `resource "aws_db_instance" "example" {
  deletion_protection = false  # 위험: 삭제 보호 없음
  ...
}`,
    after: `resource "aws_db_instance" "example" {
  deletion_protection = true   # 프로덕션 DB는 반드시 활성화
  ...
}`,
    incident: 'IaC 파이프라인 버그로 프로덕션 RDS 삭제 → 수 시간 서비스 중단 사례',
  },

  // ── CloudTrail ──────────────────────────────────────────
  CKV_CUSTOM_CT_1: {
    severity: 'HIGH',
    service: 'CloudTrail',
    ismsP: '2.11.2',
    title: 'CloudTrail 로깅 비활성화',
    reason:
      'enable_logging = false이면 AWS API 호출 기록이 남지 않아 ' +
      '침해 사고 발생 시 공격자 행위를 추적·포렌식하는 것이 불가능해집니다.',
    before: `resource "aws_cloudtrail" "example" {
  enable_logging = false  # 위험: 로그 비활성화
  ...
}`,
    after: `resource "aws_cloudtrail" "example" {
  enable_logging = true   # 항상 활성화
  ...
}`,
    incident: 'CloudTrail 비활성화는 공격자가 탐지 회피를 위해 가장 먼저 수행하는 행위',
  },

  CKV_CUSTOM_CT_2: {
    severity: 'MEDIUM',
    service: 'CloudTrail',
    ismsP: '2.7.1',
    title: 'CloudTrail 로그 파일 KMS 암호화 미적용',
    reason:
      'kms_key_id가 없으면 CloudTrail 로그가 S3에 평문으로 저장됩니다.',
    before: `resource "aws_cloudtrail" "example" {
  # kms_key_id 없음 → 평문 저장
  s3_bucket_name = aws_s3_bucket.trail.id
  ...
}`,
    after: `resource "aws_cloudtrail" "example" {
  s3_bucket_name = aws_s3_bucket.trail.id
  kms_key_id     = aws_kms_key.cloudtrail.arn
  ...
}`,
    incident: '로그 미암호화 + S3 퍼블릭 노출 조합으로 내부 API 호출 패턴 유출 사례',
  },

  CKV_CUSTOM_CT_3: {
    severity: 'MEDIUM',
    service: 'CloudTrail',
    ismsP: '2.11.2',
    title: 'CloudWatch Log Group 보존 기간 미설정',
    reason:
      'retention_in_days = 0(기본값)이면 로그가 무기한 보존되어 비용이 누적되고 ' +
      '오래된 개인정보 포함 로그가 규제 위반이 될 수 있습니다.',
    before: `resource "aws_cloudwatch_log_group" "example" {
  name = "/aws/cloudtrail"
  # retention_in_days 없음 → 무기한 보존
}`,
    after: `resource "aws_cloudwatch_log_group" "example" {
  name              = "/aws/cloudtrail"
  retention_in_days = 365  # 최소 1년 권장
}`,
    incident: '로그 보존 기간 미설정 → 무기한 개인정보 로그 보관 → 개인정보보호법 위반 리스크',
  },
}

/** check_id로 메타데이터를 조회한다. 없으면 기본값 반환. */
export function getCheckMeta(checkId) {
  return (
    CHECK_METADATA[checkId] ?? {
      severity: 'MEDIUM',
      service: 'AWS',
      ismsP: '-',
      title: checkId,
      reason: '설명 없음',
      before: '',
      after: '',
      incident: '',
    }
  )
}

/** 서비스별 위반 건수를 집계한다. */
export function groupByService(violations) {
  const counts = {}
  for (const v of violations) {
    const meta = getCheckMeta(v.check_id)
    counts[meta.service] = (counts[meta.service] ?? 0) + 1
  }
  return Object.entries(counts).map(([name, value]) => ({ name, value }))
}

/** 심각도 순서 (정렬용) */
export const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
