"""
CKV_CUSTOM_SG_3: Security Group 전 포트 개방 감지 (protocol = "-1" 또는 from/to 0~65535)
ISMS-P: 2.6.1 네트워크 접근통제
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_blocks, get_block_value, OPEN_CIDRS

METADATA = {
    "id": "CKV_CUSTOM_SG_3",
    "isms_p": "2.6.1",
    "severity": "CRITICAL",
    "title": "Security Group 전 포트 개방",
    "reason": 'protocol = "-1"(All traffic) 또는 0~65535 포트 범위 허용 시 '
              "서비스에 필요하지 않은 모든 포트가 노출되어 공격 표면이 극대화됩니다.",
    "remediation": "필요한 포트(예: 443)만 명시적으로 허용하고 protocol = \"-1\" 사용을 금지합니다.",
    "real_incident": "광범위한 포트 개방은 내부 서비스 포트(Redis 6379, Elasticsearch 9200 등) 노출로 이어짐",
}


class SGAllPortsOpenCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Security Group 인바운드에 전 포트(All traffic)가 개방되면 안 됩니다",
            id=METADATA["id"],
            categories=[CheckCategories.NETWORKING],
            supported_resources=["aws_security_group"],
        )

    def scan_resource_conf(self, conf):
        for rule in get_blocks(conf, "ingress"):
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


check = SGAllPortsOpenCheck()
