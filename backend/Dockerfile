FROM python:3.11-slim

<<<<<<< HEAD
# 작업 디렉터리 설정
WORKDIR /app

# 시스템 패키지 설치 (checkov 의존성)
=======
WORKDIR /app

>>>>>>> a4b2f72 (k8s 포트포워딩 배포 지원)
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

<<<<<<< HEAD
# Python 의존성 복사 및 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 소스 코드 전체 복사
COPY . .

# 업로드 디렉터리 생성
RUN mkdir -p uploads

# ISMS-P JSON 데이터 생성 (CSV가 있는 경우)
RUN python csv_to_json.py || true

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
=======
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p uploads

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
>>>>>>> a4b2f72 (k8s 포트포워딩 배포 지원)
