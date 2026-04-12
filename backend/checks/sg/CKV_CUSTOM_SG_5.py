"""
CKV_CUSTOM_SG_5: Security Group RDP(3389번 포트) 전체 IP 개방 감지
ISMS-P: 2.6.1 네트워크 접근통제
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_blocks, get_block_value, OPEN_CIDRS

METADATA = {
    "id": "CKV_CUSTOM_SG_5",
    "isms_p": "2.6.1",
    "severity": "CRITICAL",
    "title": "Security Group RDP(3389) 전체 개방",
    "reason": "RDP 포트 3389를 인터넷에 개방하면 BlueKeep(CVE-2019-0708) 등 "
              "원격 코드 실행 취약점 및 무차별 대입 공격에 즉시 노출됩니다.",
    "remediation": 'from_port = 3389\nto_port   = 3389\ncidr_blocks = ["YOUR_OFFICE_IP/32"]',
    "real_incident": "랜섬웨어 초기 침투의 60% 이상이 인터넷에 노출된 RDP를 통해 발생(Coveware 2023)",
}


class SGRDPOpenCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Security Group RDP(3389번 포트)가 전체 IP에 개방되면 안 됩니다",
            id=METADATA["id"],
            categories=[CheckCategories.NETWORKING],
            supported_resources=["aws_security_group"],
        )

    def scan_resource_conf(self, conf):
        for rule in get_blocks(conf, "ingress"):
            from_port = get_block_value(rule, "from_port", 0)
            to_port   = get_block_value(rule, "to_port",   0)
            try:
                from_port, to_port = int(from_port), int(to_port)
            except (TypeError, ValueError):
                continue

            if not (from_port <= 3389 <= to_port):
                continue

            cidrs = get_block_value(rule, "cidr_blocks", [])
            ipv6  = get_block_value(rule, "ipv6_cidr_blocks", [])
            all_cidrs = (cidrs if isinstance(cidrs, list) else [cidrs]) + \
                        (ipv6  if isinstance(ipv6,  list) else [ipv6])
            if any(c in OPEN_CIDRS for c in all_cidrs):
                return CheckResult.FAILED

        return CheckResult.PASSED


check = SGRDPOpenCheck()
