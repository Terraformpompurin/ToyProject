"""
CKV_CUSTOM_IAM_4: EC2 인스턴스 IMDSv2 미강제 감지
ISMS-P: 2.6.2 정보시스템 접근통제
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_blocks, get_value

METADATA = {
    "id": "CKV_CUSTOM_IAM_4",
    "isms_p": "2.6.2",
    "severity": "HIGH",
    "title": "EC2 IMDSv2 미강제 (IMDSv1 허용)",
    "reason": 'metadata_options.http_tokens = "optional"(기본값)은 IMDSv1을 허용합니다. '
              "SSRF 취약점이 있는 애플리케이션에서 IMDSv1을 통해 IAM 자격증명을 탈취할 수 있습니다.",
    "remediation": (
        'metadata_options {\n'
        '  http_endpoint               = "enabled"\n'
        '  http_tokens                 = "required"  # IMDSv2 강제\n'
        '  http_put_response_hop_limit = 1\n'
        '}'
    ),
    "real_incident": "Capital One(2019): SSRF → IMDSv1 → IAM 자격증명 탈취 → S3 1억 건 유출의 핵심 경로",
}


class IAMIMDSV2Check(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name='EC2 인스턴스에 IMDSv2(http_tokens = "required")가 강제되어야 합니다',
            id=METADATA["id"],
            categories=[CheckCategories.IAM],
            supported_resources=["aws_instance"],
        )

    def scan_resource_conf(self, conf):
        metadata_blocks = get_blocks(conf, "metadata_options")
        if not metadata_blocks:
            # metadata_options 블록 자체가 없으면 기본값(IMDSv1 허용) → FAIL
            return CheckResult.FAILED

        for block in metadata_blocks:
            http_tokens = str(get_value(block, "http_tokens", "optional")).strip().lower()
            if http_tokens != "required":
                return CheckResult.FAILED

        return CheckResult.PASSED


check = IAMIMDSV2Check()
