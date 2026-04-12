"""
CKV_CUSTOM_SG_1: Security Group 인바운드에 전체 IP(0.0.0.0/0 또는 ::/0) 개방 감지
ISMS-P: 2.6.1 네트워크 접근통제
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_blocks, get_block_value, OPEN_CIDRS

METADATA = {
    "id": "CKV_CUSTOM_SG_1",
    "isms_p": "2.6.1",
    "severity": "HIGH",
    "title": "Security Group 인바운드 전체 IP 개방",
    "reason": "0.0.0.0/0 또는 ::/0 허용 시 인터넷 전체에서 해당 포트로 접근 가능해져 "
              "무차별 대입 공격, 포트 스캔, 악성 트래픽에 노출됩니다.",
    "remediation": 'cidr_blocks = ["10.0.0.0/8"]  # 필요한 IP 대역만 허용',
    "real_incident": "Capital One(2019): 과도하게 개방된 Security Group이 초기 침투 경로가 됨",
}


class SGOpenCIDRCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Security Group 인바운드에 전체 IP(0.0.0.0/0/::/0)가 허용되면 안 됩니다",
            id=METADATA["id"],
            categories=[CheckCategories.NETWORKING],
            supported_resources=["aws_security_group"],
        )

    def scan_resource_conf(self, conf):
        for rule in get_blocks(conf, "ingress"):
            cidrs = get_block_value(rule, "cidr_blocks", [])
            ipv6_cidrs = get_block_value(rule, "ipv6_cidr_blocks", [])
            all_cidrs = (cidrs if isinstance(cidrs, list) else [cidrs]) + \
                        (ipv6_cidrs if isinstance(ipv6_cidrs, list) else [ipv6_cidrs])
            if any(c in OPEN_CIDRS for c in all_cidrs):
                return CheckResult.FAILED
        return CheckResult.PASSED


check = SGOpenCIDRCheck()
