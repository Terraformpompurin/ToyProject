"""
CKV_CUSTOM_IAM_3: IAM Access Key 리소스 생성(aws_iam_access_key) 감지
ISMS-P: 2.5.2 사용자 인증
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_value

METADATA = {
    "id": "CKV_CUSTOM_IAM_3",
    "isms_p": "2.5.2",
    "severity": "HIGH",
    "title": "Terraform으로 IAM Access Key 생성",
    "reason": "IaC 코드로 Access Key를 생성하면 키 값이 tfstate 파일에 평문으로 저장됩니다. "
              "tfstate가 유출되면 장기 자격증명이 즉시 노출됩니다.",
    "remediation": (
        "aws_iam_access_key 리소스 사용을 금지합니다.\n"
        "대안: IAM Role + Instance Profile, OIDC 기반 임시 자격증명 사용"
    ),
    "real_incident": "tfstate S3 버킷 퍼블릭 노출 → Access Key 탈취 → 계정 탈취 사례 다수",
}


class IAMAccessKeyCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="aws_iam_access_key 리소스를 Terraform으로 생성하면 안 됩니다",
            id=METADATA["id"],
            categories=[CheckCategories.IAM],
            supported_resources=["aws_iam_access_key"],
        )

    def scan_resource_conf(self, conf):
        # 리소스 자체가 존재하는 것이 위반
        user = get_value(conf, "user", "")
        if user:
            return CheckResult.FAILED
        return CheckResult.PASSED


check = IAMAccessKeyCheck()
