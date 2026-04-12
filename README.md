# Terraform Security Scanner

Terraform IaC 파일을 업로드하면 보안 취약점을 자동으로 분석해주는 웹 애플리케이션입니다.  
백엔드는 **FastAPI + Checkov**, 프론트엔드는 **React + Vite + Tailwind CSS**로 구성되어 있습니다.

---

## 목차

- [사전 요구사항](#사전-요구사항)
- [설치 방법 — Windows](#설치-방법--windows)
- [설치 방법 — macOS](#설치-방법--macos)
- [실행 방법](#실행-방법)
- [사용 방법](#사용-방법)
- [프로젝트 구조](#프로젝트-구조)

---

## 사전 요구사항

| 항목 | 권장 버전 |
|------|-----------|
| Python | 3.10 이상 |
| Node.js | 18 이상 |
| npm | 9 이상 |

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

### 3. 프로젝트 클론

```cmd
git clone <repository-url>
cd AWS_Terraform
```

### 4. 백엔드 설정

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

### 5. 프론트엔드 설정

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

### 3. 프로젝트 클론

```bash
git clone <repository-url>
cd AWS_Terraform
```

### 4. 백엔드 설정

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 5. 프론트엔드 설정

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

## 사용 방법

1. 브라우저에서 `http://localhost:5173` 접속
2. Terraform 파일(`.tf`) 또는 ZIP으로 압축한 Terraform 프로젝트 업로드
3. **스캔 시작** 버튼 클릭
4. 보안 취약점 분석 결과 확인
   - S3, IAM, RDS, CloudTrail, Security Group 등 카테고리별 취약점 표시
   - 심각도(High / Medium / Low)별 분류
   - 각 항목별 수정 가이드 제공

---

## 프로젝트 구조

```
AWS_Terraform/
├── backend/
│   ├── main.py              # FastAPI 애플리케이션 진입점
│   ├── requirements.txt     # Python 의존성
│   ├── checks/              # 커스텀 보안 체크 모듈
│   │   ├── s3/              # S3 관련 보안 체크
│   │   ├── iam/             # IAM 관련 보안 체크
│   │   ├── rds/             # RDS 관련 보안 체크
│   │   ├── sg/              # Security Group 체크
│   │   └── cloudtrail/      # CloudTrail 체크
│   └── uploads/             # 업로드 파일 임시 저장소
└── frontend/
    ├── src/                 # React 소스 코드
    ├── index.html
    ├── package.json         # Node.js 의존성
    ├── vite.config.js       # Vite 설정
    └── tailwind.config.js   # Tailwind CSS 설정
```

---

## 자주 발생하는 오류

**`checkov` 명령어를 찾을 수 없는 경우**  
가상환경이 활성화되어 있는지 확인하세요. (`venv\Scripts\activate` 또는 `source venv/bin/activate`)

**포트 충돌 오류**  
8000 또는 5173 포트가 이미 사용 중인 경우 실행 중인 다른 프로세스를 종료하거나 포트를 변경하세요.

**`npm install` 실패**  
Node.js 버전이 18 미만인 경우 업그레이드가 필요합니다.
