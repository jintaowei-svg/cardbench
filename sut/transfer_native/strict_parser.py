from __future__ import annotations

import hashlib
import inspect

from sut.transfer.common_llm import parse_decision


def parser_sha256() -> str:
    return hashlib.sha256(inspect.getsource(parse_decision).encode("utf-8")).hexdigest()


__all__ = ["parse_decision", "parser_sha256"]
