"""
CKV_CUSTOM_RDS_2: RDS 스토리지 암호화 미적용 감지
ISMS-P: 2.7.1 암호정책 적용
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_bool

METADATA = {
    "id": "CKV_CUSTOM_RDS_2",
    "isms_p": "2.7.1",
    "severity": "HIGH",
    "title": "RDS 스토리지 암호화 미적용",
    "reason": "storage_encrypted = false이면 EBS 스냅샷·스토리지 레이어 침해 시 "
              "DB 데이터가 평문으로 노출됩니다. 개인정보보호법상 암호화 의무 위반입니다.",
    "remediation": (
        "storage_encrypted = true\n"
        'kms_key_id        = aws_kms_key.rds.arn  # CMK 사용 권장'
    ),
    "real_incident": "암호화되지 않은 RDS 스냅샷 공유 오류로 고객 데이터 유출 사례 보고",
}


class RDSEncryptionCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="RDS 인스턴스/클러스터에 스토리지 암호화가 활성화되어야 합니다",
            id=METADATA["id"],
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["aws_db_instance", "aws_rds_cluster"],
        )

    def scan_resource_conf(self, conf):
        if not get_bool(conf, "storage_encrypted", False):
            return CheckResult.FAILED
        return CheckResult.PASSED


check = RDSEncryptionCheck()
