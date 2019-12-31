from typing import Tuple, Dict, Union, Generator, Optional, Mapping, overload

Unarmor = Tuple[str, Dict[str, str], bytes]

@overload
def unarmor(pem_bytes: bytes) -> Unarmor:
    ...

@overload
def unarmor(pem_bytes: bytes, multiple: bool) -> Generator[Unarmor, None, None]:
    ...

def unarmor(pem_bytes: bytes, multiple: bool = False) -> Union[Unarmor, Generator[Unarmor, None, None]]:
    ...


def armor(type_name: str, der_bytes: bytes, headers: Optional[Mapping[str, str]] = None) -> bytes:
    ...
