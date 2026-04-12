"""
CKV_CUSTOM_S3_1: S3 버킷 퍼블릭 ACL 설정 감지
ISMS-P: 2.6.2 정보시스템 접근통제
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_value

METADATA = {
    "id": "CKV_CUSTOM_S3_1",
    "isms_p": "2.6.2",
    "severity": "CRITICAL",
    "title": "S3 버킷 퍼블릭 ACL 설정",
    "reason": 'acl = "public-read" 또는 "public-read-write" 설정 시 버킷 내 모든 객체가 '
              "인터넷 전체에 공개됩니다. 개인정보·기밀 데이터 노출로 직결됩니다.",
    "remediation": 'acl = "private"  # 기본값을 항상 private으로 유지하세요',
    "real_incident": "Toyota(2023): S3 퍼블릭 버킷으로 215만 명 고객 데이터 8년간 노출",
}

PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}


class S3PublicACLCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name='S3 버킷 ACL이 public-read / public-read-write이면 안 됩니다',
            id=METADATA["id"],
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["aws_s3_bucket"],
        )

    def scan_resource_conf(self, conf):
        acl = str(get_value(conf, "acl", "private")).strip().lower()
        if acl in PUBLIC_ACLS:
            return CheckResult.FAILED
        return CheckResult.PASSED


check = S3PublicACLCheck()
