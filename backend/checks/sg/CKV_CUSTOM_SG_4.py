"""
CKV_CUSTOM_SG_4: Security Group 이그레스(아웃바운드) 전체 허용 감지
ISMS-P: 2.6.1 네트워크 접근통제
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_blocks, get_block_value, OPEN_CIDRS

METADATA = {
    "id": "CKV_CUSTOM_SG_4",
    "isms_p": "2.6.1",
    "severity": "MEDIUM",
    "title": "Security Group 이그레스 무제한 허용",
    "reason": "아웃바운드를 전체 허용하면 침해된 인스턴스에서 외부 C2 서버로의 통신, "
              "데이터 유출, 횡적 이동이 자유롭게 이루어질 수 있습니다.",
    "remediation": "egress 규칙에 허용할 목적지 IP/포트를 명시적으로 지정합니다.\n"
                   "egress {\n  from_port   = 443\n  to_port     = 443\n"
                   '  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]  # HTTPS만 허용\n}',
    "real_incident": "데이터 유출 시나리오: 아웃바운드 무제한 시 DNS tunneling, HTTPS exfiltration 가능",
}


class SGEgressUnrestrictedCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Security Group 이그레스(아웃바운드)가 전체 허용이면 안 됩니다",
            id=METADATA["id"],
            categories=[CheckCategories.NETWORKING],
            supported_resources=["aws_security_group"],
        )

    def scan_resource_conf(self, conf):
        for rule in get_blocks(conf, "egress"):
            protocol  = str(get_block_value(rule, "protocol", "")).strip()
            from_port = get_block_value(rule, "from_port", -1)
            to_port   = get_block_value(rule, "to_port",   -1)

            all_traffic = (protocol == "-1") or (protocol.lower() == "all")
            try:
                all_ports = (int(from_port) == 0 and int(to_port) == 65535)
            except (TypeError, ValueError):
                all_ports = False

            if not (all_traffic or all_ports):
                continue

            cidrs = get_block_value(rule, "cidr_blocks", [])
            ipv6  = get_block_value(rule, "ipv6_cidr_blocks", [])
            all_cidrs = (cidrs if isinstance(cidrs, list) else [cidrs]) + \
                        (ipv6  if isinstance(ipv6,  list) else [ipv6])
            if any(c in OPEN_CIDRS for c in all_cidrs):
                return CheckResult.FAILED

        return CheckResult.PASSED


check = SGEgressUnrestrictedCheck()
