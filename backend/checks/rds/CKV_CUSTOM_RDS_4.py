"""
CKV_CUSTOM_RDS_4: RDS Multi-AZ 미설정 감지
ISMS-P: 2.9.2 업무 연속성 관리
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_bool

METADATA = {
    "id": "CKV_CUSTOM_RDS_4",
    "isms_p": "2.9.2",
    "severity": "MEDIUM",
    "title": "RDS Multi-AZ 미설정",
    "reason": "Single-AZ RDS는 AZ 장애 발생 시 수 분~수십 분의 다운타임이 발생합니다. "
              "Multi-AZ는 자동 페일오버로 60~120초 내 복구를 보장합니다.",
    "remediation": "multi_az = true  # 프로덕션 DB는 반드시 활성화",
    "real_incident": "AZ 장애로 Single-AZ RDS 수십 분 다운 → 서비스 중단 사례",
}


class RDSMultiAZCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="RDS 인스턴스에 Multi-AZ가 활성화되어야 합니다",
            id=METADATA["id"],
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["aws_db_instance"],
        )

    def scan_resource_conf(self, conf):
        if not get_bool(conf, "multi_az", False):
            return CheckResult.FAILED
        return CheckResult.PASSED


check = RDSMultiAZCheck()
