# Terraform Security Scanner

Terraform IaC 파일을 업로드하면 보안 취약점을 자동으로 분석해주는 웹 애플리케이션입니다.
백엔드는 **FastAPI + Checkov**, 프론트엔드는 **React + Vite + Tailwind CSS**로 구성되어 있습니다.
**TerraGoat**는 의도적으로 취약하게 작성된 Terraform 예제 코드 모음으로, 스캐너 기능 실습에 활용합니다.

---

## 목차

- [사전 요구사항](#사전-요구사항)
- [설치 방법 — Windows](#설치-방법--windows)
- [설치 방법 — macOS](#설치-방법--macos)
- [실행 방법](#실행-방법)
- [TerraGoat로 테스트하기](#terragoat로-테스트하기)
- [사용 방법](#사용-방법)
- [프로젝트 구조](#프로젝트-구조)
- [자주 발생하는 오류](#자주-발생하는-오류)

---

## 사전 요구사항

| 항목 | 권장 버전 | 용도 |
|------|-----------|------|
| Python | 3.10 이상 | 백엔드 서버 실행 |
| Node.js | 18 이상 | 프론트엔드 빌드 |
| npm | 9 이상 | 프론트엔드 패키지 관리 |
| Terraform | 0.12 이상 | TerraGoat 실습 시 필요 |

> **Terraform은 TerraGoat 실습 시에만 필요합니다.** 웹 앱 자체 실행에는 불필요합니다.

---

## 설치 방법 — Windows

### 1. Python 설치

1. [python.org](https://www.python.org/downloads/) 에서 Python 3.10 이상 설치 파일 다운로드
2. 설치 시 **"Add Python to PATH"** 체크박스를 반드시 선택한 후 설치
3. 설치 확인:
   ```cmd
   python --version
   ```

### 2. Node.js 설치

1. [nodejs.org](https://nodejs.org/) 에서 LTS 버전 다운로드 및 설치
2. 설치 확인:
   ```cmd
   node --version
   npm --version
   ```

### 3. Terraform 설치 (TerraGoat 실습 시)

1. [developer.hashicorp.com/terraform/install](https://developer.hashicorp.com/terraform/install) 에서 Windows용 zip 파일 다운로드
2. 압축 해제 후 `terraform.exe`를 시스템 PATH에 추가
   - 예: `C:\terraform\` 폴더에 복사 후 시스템 환경변수 PATH에 `C:\terraform` 추가
3. 설치 확인:
   ```cmd
   terraform --version
   ```

### 4. 프로젝트 클론

```cmd
git clone <repository-url>
cd AWS_Terraform
```

### 5. 백엔드 설정

```cmd
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

> **참고:** `venv\Scripts\activate` 실행 시 오류가 발생하면 PowerShell에서 아래 명령어를 먼저 실행하세요:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

### 6. 프론트엔드 설정

새 터미널 창을 열고:

```cmd
cd frontend
npm install
```

---

## 설치 방법 — macOS

### 1. Python 설치

Homebrew를 사용하는 방법을 권장합니다.

**Homebrew가 없는 경우 먼저 설치:**
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**Python 설치:**
```bash
brew install python@3.11
python3 --version
```

또는 [python.org](https://www.python.org/downloads/macos/) 에서 직접 다운로드할 수 있습니다.

### 2. Node.js 설치

```bash
brew install node
node --version
npm --version
```

또는 [nodejs.org](https://nodejs.org/) 에서 macOS 설치 파일을 다운로드할 수 있습니다.

### 3. Terraform 설치 (TerraGoat 실습 시)

```bash
brew tap hashicorp/tap
brew install hashicorp/tap/terraform
terraform --version
```

또는 [developer.hashicorp.com/terraform/install](https://developer.hashicorp.com/terraform/install) 에서 macOS 바이너리를 직접 다운로드할 수 있습니다.

### 4. 프로젝트 클론

```bash
git clone <repository-url>
cd AWS_Terraform
```

### 5. 백엔드 설정

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 6. 프론트엔드 설정

새 터미널 창을 열고:

```bash
cd frontend
npm install
```

---

## 실행 방법

백엔드와 프론트엔드를 **각각 별도의 터미널**에서 실행해야 합니다.

### 백엔드 서버 실행

**Windows:**
```cmd
cd backend
venv\Scripts\activate
uvicorn main:app --reload --port 8000
```

**macOS:**
```bash
cd backend
source venv/bin/activate
uvicorn main:app --reload --port 8000
```

백엔드가 정상적으로 실행되면 `http://localhost:8000` 에서 API 서버가 시작됩니다.

### 프론트엔드 서버 실행

**Windows / macOS 공통:**
```bash
cd frontend
npm run dev
```

프론트엔드가 정상적으로 실행되면 브라우저에서 `http://localhost:5173` 에 접속하세요.

---

## TerraGoat로 테스트하기

> ⚠️ **주의:** TerraGoat의 Terraform 파일은 실제 클라우드 환경에 **절대 배포하지 마세요.** 학습 및 테스트 목적으로만 사용하세요.

`terragoat/terraform/aws/` 경로의 `.tf` 파일을 개별 또는 ZIP으로 압축해 웹 앱에 업로드하면 됩니다.

**파일별 테스트 예시:**

| 파일 | 테스트 내용 |
|------|-------------|
| `s3.tf` | S3 버킷 퍼블릭 접근, 암호화, 로깅 취약점 |
| `iam.tf` | IAM 과도한 권한, MFA 미설정 취약점 |
| `rds.tf` | RDS 암호화, 퍼블릭 접근, 백업 미설정 취약점 |
| `ec2.tf` | EC2 보안그룹, IMDSv2 미적용 취약점 |
| `eks.tf` | EKS 클러스터 보안 설정 취약점 |
| `cloudtrail` | CloudTrail 로깅 미설정 취약점 |

**AWS 전체 파일을 ZIP으로 압축해 업로드하는 방법:**

**Windows:**
```cmd
cd terragoat\terraform\aws
powershell Compress-Archive -Path * -DestinationPath aws-terragoat.zip
```

**macOS:**
```bash
cd terragoat/terraform/aws
zip -r aws-terragoat.zip .
```

---

## 사용 방법

1. 브라우저에서 `http://localhost:5173` 접속
2. Terraform 파일(`.tf`) 또는 ZIP으로 압축한 Terraform 프로젝트 업로드
3. **스캔 시작** 버튼 클릭
4. 보안 취약점 분석 결과 확인
   - S3, IAM, RDS, CloudTrail, Security Group 등 카테고리별 취약점 표시
   - 심각도(CRITICAL / HIGH / MEDIUM / LOW)별 분류
   - ISMS-P 항목 매핑 및 항목별 수정 가이드 제공
   - 파이차트 및 요약 카드로 전체 현황 시각화

---

## 프로젝트 구조

```
AWS_Terraform/
├── .gitignore
├── README.md
│
├── backend/                              # FastAPI 백엔드
│   ├── main.py                           # 애플리케이션 진입점 (파일 업로드, 스캔 API)
│   ├── requirements.txt                  # Python 의존성 (fastapi, uvicorn, checkov, sqlalchemy 등)
│   ├── uploads/                          # 업로드 파일 임시 저장소
│   └── checks/                           # 커스텀 Checkov 보안 체크 모듈
│       ├── _utils.py                     # 공통 유틸리티
│       ├── s3/                           # S3 체크 (CKV_CUSTOM_S3_1~4)
│       ├── iam/                          # IAM 체크 (CKV_CUSTOM_IAM_1~4)
│       ├── rds/                          # RDS 체크 (CKV_CUSTOM_RDS_1~5)
│       ├── sg/                           # Security Group 체크 (CKV_CUSTOM_SG_1~5)
│       └── cloudtrail/                   # CloudTrail 체크 (CKV_CUSTOM_CT_1~3)
│
├── frontend/                             # React 프론트엔드
│   ├── index.html
│   ├── package.json                      # Node.js 의존성 (react, recharts, tailwindcss 등)
│   ├── vite.config.js                    # Vite 설정 (포트 5173, /scan 프록시 → 8000)
│   ├── tailwind.config.js
│   ├── postcss.config.js
│   └── src/
│       ├── main.jsx                      # React 진입점
│       ├── App.jsx                       # 루트 컴포넌트
│       ├── index.css
│       ├── api/
│       │   └── scanner.js                # 백엔드 API 호출 함수
│       ├── components/
│       │   ├── Navbar.jsx                # 상단 네비게이션
│       │   ├── FileUpload.jsx            # 파일 업로드 UI
│       │   ├── SummaryCards.jsx          # 취약점 요약 카드
│       │   ├── ServicePieChart.jsx       # 서비스별 파이차트
│       │   ├── ViolationTable.jsx        # 취약점 목록 테이블
│       │   ├── ViolationDetail.jsx       # 취약점 상세 뷰
│       │   └── SeverityBadge.jsx         # 심각도 뱃지
│       ├── data/
│       │   └── checkMetadata.js          # 체크 메타데이터 (ISMS-P 매핑 등)
│       └── utils/
│           └── scoring.js                # 점수 계산 유틸리티
│
└── terragoat/                            # 취약 Terraform 예제 모음 (테스트용)
    ├── terraform/
    │   ├── aws/                          # AWS 취약 예제
    │   │   ├── s3.tf                     # S3 버킷
    │   │   ├── iam.tf                    # IAM 정책/역할
    │   │   ├── rds.tf                    # RDS 인스턴스
    │   │   ├── ec2.tf                    # EC2 인스턴스
    │   │   ├── eks.tf                    # EKS 클러스터
    │   │   ├── elb.tf                    # 로드밸런서
    │   │   ├── lambda.tf                 # Lambda 함수
    │   │   ├── kms.tf                    # KMS 키
    │   │   ├── ecr.tf                    # ECR 레지스트리
    │   │   ├── es.tf                     # Elasticsearch
    │   │   ├── neptune.tf                # Neptune DB
    │   │   ├── db-app.tf                 # DB 앱 인프라
    │   │   ├── consts.tf                 # 상수 정의
    │   │   └── providers.tf              # AWS 프로바이더 설정
    │   ├── azure/                        # Azure 취약 예제 (AKS, SQL, Storage 등)
    │   ├── gcp/                          # GCP 취약 예제 (GKE, GCS, BigQuery 등)
    │   ├── alicloud/                     # Alibaba Cloud 취약 예제
    │   └── oracle/                       # Oracle Cloud 취약 예제
    └── packages/                         # 취약 패키지 예제 (SCA 테스트용)
        ├── requirements.txt              # Python 취약 패키지 (django==1.2)
        ├── pom.xml                       # Java 취약 패키지
        └── node/                         # Node.js 취약 패키지
```

---

## 자주 발생하는 오류

**`checkov` 명령어를 찾을 수 없는 경우**
가상환경이 활성화되어 있는지 확인하세요. (`venv\Scripts\activate` 또는 `source venv/bin/activate`)

**포트 충돌 오류**
8000 또는 5173 포트가 이미 사용 중인 경우 실행 중인 다른 프로세스를 종료하거나 포트를 변경하세요.

**`npm install` 실패**
Node.js 버전이 18 미만인 경우 업그레이드가 필요합니다.

**`terraform` 명령어를 찾을 수 없는 경우**
Terraform 바이너리가 PATH에 등록되어 있는지 확인하세요. 웹 앱 실행 자체에는 영향이 없습니다.
