"""
CKV_CUSTOM_S3_2: S3 버킷 Public Access Block 미적용 감지
ISMS-P: 2.6.2 정보시스템 접근통제
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_bool

METADATA = {
    "id": "CKV_CUSTOM_S3_2",
    "isms_p": "2.6.2",
    "severity": "HIGH",
    "title": "S3 Public Access Block 미적용",
    "reason": "aws_s3_bucket_public_access_block 리소스의 4개 플래그가 모두 true여야 "
              "ACL·버킷정책을 통한 퍼블릭 접근을 계정 수준에서 차단할 수 있습니다.",
    "remediation": (
        'resource "aws_s3_bucket_public_access_block" "example" {\n'
        '  bucket                  = aws_s3_bucket.example.id\n'
        '  block_public_acls       = true\n'
        '  block_public_policy     = true\n'
        '  ignore_public_acls      = true\n'
        '  restrict_public_buckets = true\n'
        '}'
    ),
    "real_incident": "Toyota(2023): Public Access Block 미설정이 데이터 유출의 직접 원인",
}


class S3PublicAccessBlockCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="S3 버킷 Public Access Block 4개 항목이 모두 활성화되어야 합니다",
            id=METADATA["id"],
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["aws_s3_bucket_public_access_block"],
        )

    def scan_resource_conf(self, conf):
        flags = [
            "block_public_acls",
            "block_public_policy",
            "ignore_public_acls",
            "restrict_public_buckets",
        ]
        for flag in flags:
            if not get_bool(conf, flag, False):
                return CheckResult.FAILED
        return CheckResult.PASSED


check = S3PublicAccessBlockCheck()
