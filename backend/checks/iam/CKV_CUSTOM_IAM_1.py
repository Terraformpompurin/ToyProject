"""
CKV_CUSTOM_IAM_1: IAM 정책에 와일드카드(*) Action 또는 Resource 감지
ISMS-P: 2.5.1 사용자 계정 관리
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

import json
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_value

METADATA = {
    "id": "CKV_CUSTOM_IAM_1",
    "isms_p": "2.5.1",
    "severity": "CRITICAL",
    "title": "IAM 정책 와일드카드(*) 사용",
    "reason": 'Action = "*" 또는 Resource = "*" 조합은 사실상 관리자 권한을 부여합니다. '
              "침해 시 공격자가 AWS 계정 전체를 장악할 수 있습니다.",
    "remediation": (
        "최소 권한 원칙(PoLP)을 적용합니다.\n"
        '# 나쁜 예\n  Action   = ["*"]\n  Resource = ["*"]\n\n'
        '# 좋은 예\n  Action   = ["s3:GetObject", "s3:PutObject"]\n'
        '  Resource = ["arn:aws:s3:::my-bucket/*"]'
    ),
    "real_incident": "Capital One(2019): 과도한 IAM 권한(와일드카드)이 S3 전체 접근 허용 → 1억 건 데이터 유출",
}


def _has_wildcard(policy_str: str) -> bool:
    """JSON 정책 문자열에서 Action/Resource 와일드카드 여부를 확인한다."""
    try:
        policy = json.loads(policy_str) if isinstance(policy_str, str) else policy_str
    except (json.JSONDecodeError, TypeError):
        return False

    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        effect = stmt.get("Effect", "Allow")
        if effect != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return True
    return False


class IAMWildcardPolicyCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="IAM 정책에 Action=* 과 Resource=* 조합이 있으면 안 됩니다",
            id=METADATA["id"],
            categories=[CheckCategories.IAM],
            supported_resources=["aws_iam_policy", "aws_iam_role_policy"],
        )

    def scan_resource_conf(self, conf):
        policy_str = get_value(conf, "policy", "")
        if policy_str and _has_wildcard(policy_str):
            return CheckResult.FAILED
        return CheckResult.PASSED


check = IAMWildcardPolicyCheck()
