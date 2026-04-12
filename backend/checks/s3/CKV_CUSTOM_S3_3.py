"""
CKV_CUSTOM_S3_3: S3 버킷 서버 사이드 암호화 미적용 감지
ISMS-P: 2.7.1 암호정책 적용
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.normpath(
    _os.path.join(_os.path.abspath(__file__), '..', '..', '..')))

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checks._utils import get_blocks, get_value

METADATA = {
    "id": "CKV_CUSTOM_S3_3",
    "isms_p": "2.7.1",
    "severity": "HIGH",
    "title": "S3 버킷 서버 사이드 암호화 미적용",
    "reason": "S3 버킷에 SSE(Server-Side Encryption)가 없으면 저장된 객체가 "
              "평문으로 보관되어, 스토리지 레이어 침해 시 데이터가 즉시 노출됩니다.",
    "remediation": (
        'resource "aws_s3_bucket_server_side_encryption_configuration" "example" {\n'
        '  bucket = aws_s3_bucket.example.id\n'
        '  rule {\n'
        '    apply_server_side_encryption_by_default {\n'
        '      sse_algorithm = "aws:kms"\n'
        '    }\n'
        '  }\n'
        '}'
    ),
    "real_incident": "암호화되지 않은 S3 버킷은 내부자 위협·스토리지 스냅샷 탈취 시 즉각 노출",
}


class S3EncryptionCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="S3 버킷에 서버 사이드 암호화(SSE)가 설정되어야 합니다",
            id=METADATA["id"],
            categories=[CheckCategories.ENCRYPTION],
            # 신구 두 리소스 형태 모두 검사
            supported_resources=[
                "aws_s3_bucket",
                "aws_s3_bucket_server_side_encryption_configuration",
            ],
        )

    def scan_resource_conf(self, conf):
        # 신형: aws_s3_bucket_server_side_encryption_configuration 리소스 자체가 존재하면 PASS
        if "rule" in conf:
            rules = get_blocks(conf, "rule")
            for rule in rules:
                apply_block = get_blocks(rule, "apply_server_side_encryption_by_default")
                if apply_block:
                    algo = get_value(apply_block[0], "sse_algorithm", "")
                    if algo:
                        return CheckResult.PASSED
            return CheckResult.FAILED

        # 구형: aws_s3_bucket 내 server_side_encryption_configuration 블록
        sse_blocks = get_blocks(conf, "server_side_encryption_configuration")
        if not sse_blocks:
            return CheckResult.FAILED

        for sse in sse_blocks:
            for rule in get_blocks(sse, "rule"):
                apply_block = get_blocks(rule, "apply_server_side_encryption_by_default")
                if apply_block:
                    algo = get_value(apply_block[0], "sse_algorithm", "")
                    if algo:
                        return CheckResult.PASSED

        return CheckResult.FAILED


check = S3EncryptionCheck()
