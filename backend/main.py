from typing import Annotated, Any
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import tempfile
import subprocess
import os
import json
import shutil
import zipfile

print("=== LOADED MAIN.PY ===")

# 커스텀 체크 디렉터리 — main.py 기준 상대경로로 고정
CHECKS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "checks")
# backend/ 를 PYTHONPATH에 추가해 체크 파일 안의 'from checks._utils import ...' 가 동작하도록 함
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))


def _normalize_checkov_output(parsed: Any) -> dict:
    """
    Checkov JSON 출력을 단일 dict 형태로 정규화한다.

    Checkov는 스캔 대상에 따라 두 가지 형태로 출력한다.
      - 단일 dict : { "results": { "failed_checks": [...], ... } }
      - 배열      : [ { "results": {...} }, { "results": {...} } ]  ← 여러 프레임워크

    배열인 경우 모든 결과를 하나의 dict로 병합해서 반환한다.
    """
    if not isinstance(parsed, list):
        return parsed

    merged: dict[str, list] = {
        "failed_checks":  [],
        "passed_checks":  [],
        "skipped_checks": [],
    }
    for item in parsed:
        if not isinstance(item, dict):
            continue
        results = item.get("results", {})
        for key in merged:
            merged[key].extend(results.get(key, []))

    return {"results": merged}


def safe_extract_zip(zip_path: str, extract_dir: str) -> None:
    """
    Zip Slip 공격 방지용 안전한 ZIP 압축 해제.
    - 경로가 extract_dir 바깥을 벗어나면 건너뜀
    - macOS 아티팩트(__MACOSX/, ._* 파일)는 건너뜀
    """
    extract_dir = os.path.realpath(extract_dir)

    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            parts = member.filename.replace("\\", "/").split("/")

            # macOS 아티팩트 건너뜀
            if "__MACOSX" in parts:
                continue
            if any(p.startswith("._") for p in parts):
                continue

            # Zip Slip 방지
            target_path = os.path.realpath(os.path.join(extract_dir, member.filename))
            if not target_path.startswith(extract_dir + os.sep):
                if target_path != extract_dir:
                    continue

            if member.is_dir():
                os.makedirs(target_path, exist_ok=True)
                continue

            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with zf.open(member) as src, open(target_path, "wb") as dst:
                shutil.copyfileobj(src, dst)


def find_tf_root(base_dir: str) -> str:
    """
    압축 해제 디렉터리에서 .tf 파일이 가장 많은 최상위 디렉터리를 반환.
    - .tf 파일이 base_dir 바로 아래에 있으면 base_dir 반환
    - 단일 서브디렉터리 안에만 .tf가 있으면 그 서브디렉터리 반환
    - 여러 서브디렉터리에 분산되어 있으면 .tf가 가장 많은 디렉터리 반환
    - .tf 파일이 아예 없으면 base_dir 반환 (Checkov가 에러 처리)
    """
    best_dir = base_dir
    best_count = 0

    for dirpath, _, filenames in os.walk(base_dir):
        tf_count = sum(1 for f in filenames if f.endswith(".tf"))
        if tf_count > best_count:
            best_count = tf_count
            best_dir = dirpath

    return best_dir


app = FastAPI(
    title="Checkov Scanner API",
    description="Upload a ZIP file containing Terraform files and scan it with Checkov",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
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
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file uploaded.")

        # 파일 저장
        with open(upload_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        # 경우 1: ZIP 파일
        if file.filename.lower().endswith(".zip"):
            os.makedirs(extract_dir, exist_ok=True)

            try:
                safe_extract_zip(upload_path, extract_dir)
            except zipfile.BadZipFile:
                raise HTTPException(status_code=400, detail="Invalid ZIP file.")

            scan_target_dir = find_tf_root(extract_dir)

        # 경우 2: 단일 .tf 파일
        elif file.filename.lower().endswith(".tf"):
            scan_target_dir = temp_dir

        else:
            raise HTTPException(status_code=400, detail="Only .zip or .tf files are allowed.")

        # 업로드 파일명에서 경로 구분자 제거 (Windows 호환)
        safe_filename = os.path.basename(file.filename)

        # Checkov 실행
        # - PYTHONPATH: 체크 파일이 로드될 때 'from checks._utils import ...' 해결
        # - --external-checks-dir: 커스텀 체크 디렉터리 (체크 파일이 자체적으로도 sys.path 보정)
        # - --framework terraform: terraform 체크만 실행해 불필요한 프레임워크 제외
        env = os.environ.copy()
        existing_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            _BACKEND_DIR + os.pathsep + existing_pp
            if existing_pp
            else _BACKEND_DIR
        )

        result = subprocess.run(
            [
                "checkov",
                "-d", scan_target_dir,
                "--external-checks-dir", CHECKS_DIR,
                "--framework", "terraform",
                "-o", "json",
            ],
            capture_output=True,
            text=True,
            env=env,
        )

        # returncode 0 = 위반 없음 / 1 = 위반 있음 / 그 외 = 실행 오류
        if result.returncode not in [0, 1]:
            return {
                "success": False,
                "error": result.stderr.strip() or "Checkov execution failed.",
                "_debug": {
                    "returncode":    result.returncode,
                    "scan_dir":      scan_target_dir,
                    "stderr":        result.stderr[:1000],
                    "stdout_prefix": result.stdout[:500],
                },
            }

        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {
                "success": False,
                "error": "Checkov JSON 파싱 실패. 파일 형식을 확인하세요.",
                "_debug": {
                    "returncode":    result.returncode,
                    "scan_dir":      scan_target_dir,
                    "stderr":        result.stderr[:1000],
                    "stdout_prefix": result.stdout[:500],
                },
            }

        # 배열 / 단일 dict 두 형태 모두 정규화
        parsed = _normalize_checkov_output(parsed)

        failed_checks  = parsed.get("results", {}).get("failed_checks",  [])
        passed_checks  = parsed.get("results", {}).get("passed_checks",  [])
        skipped_checks = parsed.get("results", {}).get("skipped_checks", [])

        # tf 파일 수 확인 (디버그용)
        tf_count = sum(
            1 for _, _, files in os.walk(scan_target_dir)
            for f in files if f.endswith(".tf")
        )

        return {
            "success": True,
            "filename": safe_filename,
            "summary": {
                "failed":  len(failed_checks),
                "passed":  len(passed_checks),
                "skipped": len(skipped_checks),
            },
            "data": parsed,
            # 개발 중 디버깅용 — 프로덕션 전 제거
            "_debug": {
                "scan_dir":  scan_target_dir,
                "tf_count":  tf_count,
                "returncode": result.returncode,
                "stderr_snippet": result.stderr[:300] if result.stderr else "",
            },
        }

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)