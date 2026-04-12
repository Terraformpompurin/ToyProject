"""
CKV_CUSTOM_RDS_5: RDS 삭제 보호 미활성 감지
ISMS-P: 2.9.1 백업 및 복구
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_bool

METADATA = {
    "id": "CKV_CUSTOM_RDS_5",
    "isms_p": "2.9.1",
    "severity": "MEDIUM",
    "title": "RDS 삭제 보호 미활성",
    "reason": "deletion_protection = false이면 terraform destroy 또는 콘솔 실수로 "
              "DB 인스턴스가 즉시 삭제될 수 있습니다. 복구하려면 최신 스냅샷에서 새로 생성해야 합니다.",
    "remediation": "deletion_protection = true  # 프로덕션 DB는 반드시 활성화",
    "real_incident": "IaC 자동화 파이프라인 버그로 프로덕션 RDS 삭제 → 수 시간 서비스 중단 사례",
}


class RDSDeletionProtectionCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="RDS 인스턴스/클러스터에 삭제 보호가 활성화되어야 합니다",
            id=METADATA["id"],
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["aws_db_instance", "aws_rds_cluster"],
        )

    def scan_resource_conf(self, conf):
        if not get_bool(conf, "deletion_protection", False):
            return CheckResult.FAILED
        return CheckResult.PASSED


check = RDSDeletionProtectionCheck()
