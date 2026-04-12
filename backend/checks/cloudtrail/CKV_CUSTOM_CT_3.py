"""
CKV_CUSTOM_CT_3: CloudWatch Log Group 보존 기간 미설정 감지
ISMS-P: 2.11.2 로그 관리
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_value

METADATA = {
    "id": "CKV_CUSTOM_CT_3",
    "isms_p": "2.11.2",
    "severity": "MEDIUM",
    "title": "CloudWatch Log Group 보존 기간 미설정",
    "reason": "retention_in_days = 0(기본값)이면 로그가 무기한 보존됩니다. "
              "불필요한 비용이 발생하고, 오래된 로그 보관이 오히려 개인정보 규제 위반이 될 수 있습니다. "
              "ISMS-P는 최소 1년(365일) 이상 보존을 권고합니다.",
    "remediation": "retention_in_days = 365  # 최소 1년, 규정에 따라 조정",
    "real_incident": "로그 보존 기간 미설정 → 무기한 개인정보 포함 로그 보관 → 개인정보보호법 위반 리스크",
}

# AWS가 허용하는 보존 기간 값 목록 (0 = 무기한)
VALID_RETENTION_VALUES = {
    1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653
}
MIN_RETENTION_DAYS = 90  # 최소 권고 보존 기간


class CloudWatchRetentionCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name=f"CloudWatch Log Group 보존 기간이 {MIN_RETENTION_DAYS}일 이상으로 설정되어야 합니다",
            id=METADATA["id"],
            categories=[CheckCategories.LOGGING],
            supported_resources=["aws_cloudwatch_log_group"],
        )

    def scan_resource_conf(self, conf):
        retention = get_value(conf, "retention_in_days", 0)
        try:
            retention = int(retention)
        except (TypeError, ValueError):
            return CheckResult.FAILED

        # 0 = 무기한(미설정) 또는 MIN_RETENTION_DAYS 미만이면 FAIL
        if retention == 0 or retention < MIN_RETENTION_DAYS:
            return CheckResult.FAILED

        return CheckResult.PASSED


check = CloudWatchRetentionCheck()
