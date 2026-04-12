"""
CKV_CUSTOM_SG_2: Security Group SSH(22번 포트) 전체 IP 개방 감지
ISMS-P: 2.6.1 네트워크 접근통제
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_blocks, get_block_value, OPEN_CIDRS

METADATA = {
    "id": "CKV_CUSTOM_SG_2",
    "isms_p": "2.6.1",
    "severity": "CRITICAL",
    "title": "Security Group SSH(22) 전체 개방",
    "reason": "SSH 포트를 인터넷 전체에 개방하면 브루트포스 공격, 크리덴셜 스터핑 등에 "
              "서버가 직접 노출됩니다. Shodan 등 스캐너가 수초 내에 탐지합니다.",
    "remediation": 'from_port = 22\nto_port   = 22\ncidr_blocks = ["YOUR_OFFICE_IP/32"]  # 관리 IP만 허용',
    "real_incident": "Capital One(2019): EC2 인스턴스 SSH 22번 포트 전체 개방이 공격 진입점으로 활용됨",
}


class SGSSHOpenCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Security Group SSH(22번 포트)가 전체 IP에 개방되면 안 됩니다",
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

            if not (from_port <= 22 <= to_port):
                continue

            cidrs     = get_block_value(rule, "cidr_blocks",      [])
            ipv6      = get_block_value(rule, "ipv6_cidr_blocks",  [])
            all_cidrs = (cidrs if isinstance(cidrs, list) else [cidrs]) + \
                        (ipv6  if isinstance(ipv6,  list) else [ipv6])
            if any(c in OPEN_CIDRS for c in all_cidrs):
                return CheckResult.FAILED

        return CheckResult.PASSED


check = SGSSHOpenCheck()
