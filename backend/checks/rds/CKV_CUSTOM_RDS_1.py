"""
CKV_CUSTOM_RDS_1: RDS 인스턴스/클러스터 퍼블릭 접근 허용 감지
ISMS-P: 2.6.1 네트워크 접근통제
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_bool

METADATA = {
    "id": "CKV_CUSTOM_RDS_1",
    "isms_p": "2.6.1",
    "severity": "CRITICAL",
    "title": "RDS publicly_accessible = true",
    "reason": "DB 인스턴스가 인터넷에 직접 노출되면 SQL 인젝션, 무차별 대입, "
              "알려진 DB 엔진 취약점 공격에 직접 노출됩니다.",
    "remediation": 'publicly_accessible = false  # 기본값이 false이나 명시적으로 선언 권장',
    "real_incident": "Toyota(2023): RDS publicly_accessible 설정이 DB 직접 노출 원인 중 하나로 분석됨",
}


class RDSPublicAccessCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="RDS 인스턴스가 publicly_accessible = true이면 안 됩니다",
            id=METADATA["id"],
            categories=[CheckCategories.NETWORKING],
            supported_resources=["aws_db_instance", "aws_rds_cluster_instance"],
        )

    def scan_resource_conf(self, conf):
        if get_bool(conf, "publicly_accessible", False):
            return CheckResult.FAILED
        return CheckResult.PASSED


check = RDSPublicAccessCheck()
