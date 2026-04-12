"""
CKV_CUSTOM_CT_1: CloudTrail 로깅 비활성화 감지
ISMS-P: 2.11.2 로그 관리
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_bool

METADATA = {
    "id": "CKV_CUSTOM_CT_1",
    "isms_p": "2.11.2",
    "severity": "HIGH",
    "title": "CloudTrail 로깅 비활성화",
    "reason": "enable_logging = false이면 AWS API 호출 기록이 남지 않아 "
              "침해 사고 발생 시 공격자 행위를 추적·포렌식하는 것이 불가능해집니다.",
    "remediation": "enable_logging = true  # 기본값은 true이나 명시적으로 선언 권장",
    "real_incident": "CloudTrail 비활성화는 공격자가 탐지를 피하기 위해 가장 먼저 수행하는 행위 중 하나",
}


class CloudTrailLoggingCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="CloudTrail 로깅이 활성화되어야 합니다 (enable_logging = true)",
            id=METADATA["id"],
            categories=[CheckCategories.LOGGING],
            supported_resources=["aws_cloudtrail"],
        )

    def scan_resource_conf(self, conf):
        # enable_logging 기본값은 true이므로, 명시적으로 false인 경우만 FAIL
        if not get_bool(conf, "enable_logging", True):
            return CheckResult.FAILED
        return CheckResult.PASSED


check = CloudTrailLoggingCheck()
