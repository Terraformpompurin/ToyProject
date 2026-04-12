"""
CKV_CUSTOM_RDS_3: RDS 자동 백업 미설정 감지 (backup_retention_period < 7)
ISMS-P: 2.9.1 백업 및 복구
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_value

METADATA = {
    "id": "CKV_CUSTOM_RDS_3",
    "isms_p": "2.9.1",
    "severity": "MEDIUM",
    "title": "RDS 백업 보존 기간 부족 (7일 미만)",
    "reason": "backup_retention_period = 0이면 자동 백업이 완전히 비활성화됩니다. "
              "랜섬웨어·실수 삭제 발생 시 복구가 불가능합니다. "
              "ISMS-P는 최소 7일 이상 보존을 권고합니다.",
    "remediation": "backup_retention_period = 7  # 최소 7일, 중요 DB는 30일 이상 권장",
    "real_incident": "백업 미설정 상태에서 랜섬웨어 피해 → DB 완전 손실 사례 다수",
}

MIN_RETENTION_DAYS = 7


class RDSBackupCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name=f"RDS 백업 보존 기간이 {MIN_RETENTION_DAYS}일 이상이어야 합니다",
            id=METADATA["id"],
            categories=[CheckCategories.BACKUP_AND_RECOVERY],
            supported_resources=["aws_db_instance", "aws_rds_cluster"],
        )

    def scan_resource_conf(self, conf):
        retention = get_value(conf, "backup_retention_period", 0)
        try:
            if int(retention) < MIN_RETENTION_DAYS:
                return CheckResult.FAILED
        except (TypeError, ValueError):
            return CheckResult.FAILED
        return CheckResult.PASSED


check = RDSBackupCheck()
