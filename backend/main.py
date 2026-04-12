from typing import Annotated, Any
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import tempfile
import subprocess
import os
import json
import shutil
import zipfile

print("=== [INFO] Terraform Security Scanner Backend Loaded ===")

# --- 경로 설정 ---
# main.py 파일이 있는 디렉터리 경로
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 커스텀 체크 디렉터리 (기존 checks 폴더)
CHECKS_DIR = os.path.join(BASE_DIR, "checks")
# 전처리된 ISMS-P 데이터 파일 경로
ISMS_JSON_PATH = os.path.join(BASE_DIR, "isms_p_data.json")

# --- 1. ISMS-P 데이터 로드 ---
# csv_to_json.py를 통해 생성한 json 파일을 서버 시작 시 읽어옵니다.
isms_info = {}
if os.path.exists(ISMS_JSON_PATH):
    with open(ISMS_JSON_PATH, 'r', encoding='utf-8') as f:
        isms_info = json.load(f)
    print(f"=== [SUCCESS] Loaded {len(isms_info)} ISMS-P items ===")
else:
    print("=== [WARNING] isms_p_data.json not found! ===")

# --- 2. 사고 사례 기반 Checkov-ISMS-P 매핑 테이블 ---
# PDF 개요의 4대 사고 사례를 기반으로 주요 ID를 ISMS-P 번호와 연결합니다.
RULE_MAPPING = {
    # [Toyota 사고] RDS 퍼블릭 노출 및 암호화
    "CKV_AWS_157": "2.6.1",   # RDS 퍼블릭 액세스 허용
    "CKV_AWS_16":  "2.7.1",   # RDS 암호화 미설정
    "CKV_AWS_118": "2.9.3",   # RDS 백업 설정 미흡
    
    # [Capital One 사고] IMDSv1 및 IAM 과권한
    "CKV_AWS_79":  "2.10.2",  # IMDSv2 강제 미적용
    "CKV_AWS_1":   "2.5.1",   # IAM 권한 과다 부여
    "CKV_AWS_107": "2.6.1",   # 보안 그룹 이그레스 제한 미흡
    
    # [S3 유출 사고] 퍼블릭 접근 및 암호화
    "CKV_AWS_19":  "2.10.1",  # S3 퍼블릭 접근 차단 미설정
    "CKV_AWS_20":  "2.10.1",  # S3 버킷 ACL 퍼블릭 허용
    "CKV_AWS_145": "2.7.1",   # S3 서버측 암호화 미설정
    
    # [GitHub 키 유출] 하드코딩
    "CKV_SECRET_6": "2.10.2"  # 테라폼 내 하드코딩된 비밀번호/키
}

# --- 헬퍼 함수들 ---

def _normalize_checkov_output(parsed: Any) -> dict:
    """Checkov의 다양한 출력 형식을 단일 dict로 병합합니다."""
    if not isinstance(parsed, list):
        return parsed
    merged = {"failed_checks": [], "passed_checks": [], "skipped_checks": []}
    for item in parsed:
        if not isinstance(item, dict): continue
        results = item.get("results", {})
        for key in merged:
            merged[key].extend(results.get(key, []))
    return {"results": merged}

def safe_extract_zip(zip_path: str, extract_dir: str) -> None:
    """Zip Slip 공격을 방지하며 압축을 해제합니다."""
    extract_dir = os.path.realpath(extract_dir)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            target_path = os.path.realpath(os.path.join(extract_dir, member.filename))
            if not target_path.startswith(extract_dir + os.sep) and target_path != extract_dir:
                continue
            if member.is_dir():
                os.makedirs(target_path, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with zf.open(member) as src, open(target_path, "wb") as dst:
                shutil.copyfileobj(src, dst)

def find_tf_root(base_dir: str) -> str:
    """.tf 파일이 가장 많은 디렉터리를 찾아 반환합니다."""
    best_dir, best_count = base_dir, 0
    for dirpath, _, filenames in os.walk(base_dir):
        count = sum(1 for f in filenames if f.endswith(".tf"))
        if count > best_count:
            best_count, best_dir = count, dirpath
    return best_dir

# --- FastAPI 앱 설정 ---

app = FastAPI(title="Terraform ISMS-P Scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # 테스트 편의를 위해 전체 허용 (배포 시 수정 필요)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/scan")
async def scan_file(
    file: Annotated[UploadFile, File(description="ZIP or single .tf file")]
) -> dict[str, Any]:
    temp_dir = tempfile.mkdtemp()
    upload_path = os.path.join(temp_dir, file.filename)
    extract_dir = os.path.join(temp_dir, "extracted")

    try:
        # 1. 파일 저장
        with open(upload_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        # 2. 스캔 대상 결정
        if file.filename.lower().endswith(".zip"):
            os.makedirs(extract_dir, exist_ok=True)
            safe_extract_zip(upload_path, extract_dir)
            scan_target_dir = find_tf_root(extract_dir)
        elif file.filename.lower().endswith(".tf"):
            scan_target_dir = temp_dir
        else:
            raise HTTPException(status_code=400, detail="Only .zip or .tf files are allowed.")

        # 3. Checkov 실행 (인코딩 에러 방지 설정 포함)
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8" # 한글 인코딩 에러 방지
        env["PYTHONUTF8"] = "1"           # 파이썬 UTF-8 모드 강제
        env["PYTHONPATH"] = BASE_DIR + os.pathsep + env.get("PYTHONPATH", "")

        result = subprocess.run(
            [
                "checkov", "-d", scan_target_dir,
                "--external-checks-dir", CHECKS_DIR,
                "--framework", "terraform",
                "-o", "json",
            ],
            capture_output=True, text=True, env=env, shell=True
        )

        # 4. 결과 파싱 및 전처리
        if result.returncode not in [0, 1]:
            return {"success": False, "error": "Checkov 실행 실패", "_debug": result.stderr}

        try:
            parsed = _normalize_checkov_output(json.loads(result.stdout))
        except:
            return {"success": False, "error": "JSON 파싱 실패"}

        failed_checks = parsed.get("results", {}).get("failed_checks", [])
        
        # 5. ISMS-P 데이터 및 매핑 데이터 결합
        processed_results = []
        for check in failed_checks:
            check_id = check.get("check_id")
            
            # 매핑된 ISMS-P 번호 가져오기 (없으면 '기타')
            isms_no = RULE_MAPPING.get(check_id, "기타")
            # JSON 데이터에서 해당 번호의 상세 정보 가져오기
            isms_detail = isms_info.get(isms_no, {
                "title": "일반 보안 준수",
                "content": "클라우드 보안 설정 표준을 확인하세요."
            })

            processed_results.append({
                "check_id": check_id,
                "severity": check.get("severity", "MEDIUM"),
                "check_name": check.get("check_name"),
                "resource": check.get("resource"),
                "file_path": check.get("file_path"),
                "line_range": check.get("file_line_range"),
                # 우리가 추가한 핵심 데이터
                "isms_no": isms_no,
                "isms_title": isms_detail["title"],
                "isms_content": isms_detail["content"],
                # 나중에 프론트에서 코드 제안을 보여줄 때 사용
                "guideline": f"# [ISMS-P {isms_no} 위반]\n# {isms_detail['title']} 대응 필요" 
            })

        # 6. 최종 응답
        return {
            "success": True,
            "filename": os.path.basename(file.filename),
            "summary": {
                "total_failed": len(failed_checks),
                "critical": sum(1 for c in failed_checks if c.get("severity") == "CRITICAL"),
                "high": sum(1 for c in failed_checks if c.get("severity") == "HIGH"),
                "passed": len(parsed.get("results", {}).get("passed_checks", []))
            },
            "results": processed_results
        }

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)