from collections.abc import Mapping
from typing import Optional

def unarmor(pem_bytes: bytes) -> tuple[str, dict[str, str], bytes]:
    ...

def armor(type_name: str, der_bytes: bytes, headers: Optional[Mapping[str, str]] = None) -> bytes:
    ...
