"""
CKV_CUSTOM_IAM_2: IAM User에 정책 직접 연결(inline/managed) 감지
ISMS-P: 2.5.1 사용자 계정 관리
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_value

METADATA = {
    "id": "CKV_CUSTOM_IAM_2",
    "isms_p": "2.5.1",
    "severity": "MEDIUM",
    "title": "IAM User에 정책 직접 연결",
    "reason": "User에 정책을 직접 연결하면 권한 관리가 개인별로 파편화되어 "
              "변경·감사가 어려워지고, 퇴직자 정리 누락 위험이 높아집니다. "
              "그룹/Role 기반 정책 관리가 모범 사례입니다.",
    "remediation": (
        "aws_iam_user_policy 대신 aws_iam_group_policy + aws_iam_user_group_membership 사용\n"
        "또는 Role 기반 접근 제어(RBAC)로 전환합니다."
    ),
    "real_incident": "User 직접 연결 정책은 감사 시 권한 추적 복잡도를 크게 높여 침해 탐지를 지연시킴",
}


class IAMUserDirectPolicyCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="IAM User에 정책을 직접 연결(aws_iam_user_policy)하면 안 됩니다",
            id=METADATA["id"],
            categories=[CheckCategories.IAM],
            supported_resources=["aws_iam_user_policy"],
        )

    def scan_resource_conf(self, conf):
        # 리소스 자체가 존재하는 것 자체가 위반
        user = get_value(conf, "user", "")
        if user:
            return CheckResult.FAILED
        return CheckResult.PASSED


check = IAMUserDirectPolicyCheck()
