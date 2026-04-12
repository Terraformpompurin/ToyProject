"""
Checkov custom check 공통 헬퍼.

Checkov가 HCL을 파싱한 conf 딕셔너리는 값이 대부분 리스트로 감싸져 있고,
인라인 블록(ingress/egress 등)은 이중 리스트로 감싸지는 경우가 있다.
이 모듈은 그 구조를 일관되게 풀어주는 유틸 함수를 제공한다.
"""
from __future__ import annotations
from typing import Any


def get_value(conf: dict, key: str, default: Any = None) -> Any:
    """conf[key] 의 첫 번째 실제 값을 반환한다."""
    raw = conf.get(key, [default])
    if isinstance(raw, list) and raw:
        return raw[0]
    return raw


def get_bool(conf: dict, key: str, default: bool = False) -> bool:
    """Boolean 속성을 안전하게 가져온다 (문자열 "true"/"false" 도 처리)."""
    val = get_value(conf, key, default)
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() == "true"
    return bool(val)


def get_blocks(conf: dict, key: str) -> list[dict]:
    """
    인라인 블록 목록을 반환한다.
    [[{...}, {...}]] 또는 [{...}, {...}] 두 형태를 모두 처리한다.
    """
    raw = conf.get(key, [])
    if not raw:
        return []
    # 이중 리스트([[...]]) 형태
    if isinstance(raw[0], list):
        return raw[0]
    # 단일 리스트([{...}]) 형태
    if isinstance(raw[0], dict):
        return raw
    return []


def get_block_value(block: dict, key: str, default: Any = None) -> Any:
    """블록 내부 값을 꺼낸다 (블록 내부도 리스트 래핑이 있을 수 있음)."""
    raw = block.get(key, [default])
    if isinstance(raw, list) and raw:
        inner = raw[0]
        # cidr_blocks 같은 경우 [["0.0.0.0/0"]] 이중 리스트일 수 있음
        if isinstance(inner, list):
            return inner
        return inner
    return raw


OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
