"""
CKV_CUSTOM_CT_2: CloudTrail 로그 파일 암호화(KMS) 미적용 감지
ISMS-P: 2.7.1 암호정책 적용 / 2.11.2 로그 관리
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_value

METADATA = {
    "id": "CKV_CUSTOM_CT_2",
    "isms_p": "2.7.1",
    "severity": "MEDIUM",
    "title": "CloudTrail 로그 파일 KMS 암호화 미적용",
    "reason": "kms_key_id가 없으면 CloudTrail 로그가 S3에 평문으로 저장됩니다. "
              "S3 버킷 침해 시 API 호출 이력 전체가 공격자에게 노출됩니다.",
    "remediation": (
        'kms_key_id = aws_kms_key.cloudtrail.arn\n\n'
        '# KMS 키 생성 예시\n'
        'resource "aws_kms_key" "cloudtrail" {\n'
        '  description             = "CloudTrail log encryption key"\n'
        '  enable_key_rotation     = true\n'
        '}'
    ),
    "real_incident": "로그 파일 미암호화 + S3 퍼블릭 노출 조합으로 내부 API 호출 패턴 유출 사례",
}


class CloudTrailEncryptionCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="CloudTrail 로그 파일이 KMS로 암호화되어야 합니다",
            id=METADATA["id"],
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["aws_cloudtrail"],
        )

    def scan_resource_conf(self, conf):
        kms_key = get_value(conf, "kms_key_id", None)
        if not kms_key:
            return CheckResult.FAILED
        return CheckResult.PASSED


check = CloudTrailEncryptionCheck()
