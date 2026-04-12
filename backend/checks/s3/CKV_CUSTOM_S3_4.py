"""
CKV_CUSTOM_S3_4: S3 버킷 버전 관리 미설정 감지
ISMS-P: 2.9.1 백업 및 복구
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_blocks, get_value, get_bool

METADATA = {
    "id": "CKV_CUSTOM_S3_4",
    "isms_p": "2.9.1",
    "severity": "MEDIUM",
    "title": "S3 버킷 버전 관리 미설정",
    "reason": "버전 관리가 비활성화된 버킷은 실수로 삭제·덮어쓴 객체를 복구할 수 없고, "
              "랜섬웨어로 암호화된 파일을 이전 버전으로 복원하는 것도 불가능합니다.",
    "remediation": (
        'resource "aws_s3_bucket_versioning" "example" {\n'
        '  bucket = aws_s3_bucket.example.id\n'
        '  versioning_configuration {\n'
        '    status = "Enabled"\n'
        '  }\n'
        '}'
    ),
    "real_incident": "랜섬웨어 피해 기업 중 S3 버전관리 미설정으로 복구 불가 사례 다수 보고",
}


class S3VersioningCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="S3 버킷에 버전 관리(Versioning)가 활성화되어야 합니다",
            id=METADATA["id"],
            categories=[CheckCategories.BACKUP_AND_RECOVERY],
            supported_resources=[
                "aws_s3_bucket",
                "aws_s3_bucket_versioning",
            ],
        )

    def scan_resource_conf(self, conf):
        # 신형: aws_s3_bucket_versioning
        if "versioning_configuration" in conf:
            for vc in get_blocks(conf, "versioning_configuration"):
                status = str(get_value(vc, "status", "")).strip().lower()
                if status == "enabled":
                    return CheckResult.PASSED
            return CheckResult.FAILED

        # 구형: aws_s3_bucket 내 versioning 블록
        for v in get_blocks(conf, "versioning"):
            if get_bool(v, "enabled", False):
                return CheckResult.PASSED

        return CheckResult.FAILED


check = S3VersioningCheck()
