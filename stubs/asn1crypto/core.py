from __future__ import annotations
from typing import ByteString, Union, Dict, Any as _Any, Optional, TypeVar, Type, Iterator


ASN1_VALUE = TypeVar("ASN1_VALUE", bound="Asn1Value")


class Asn1Value:
    def __init__(self, value: Optional[_Any] = None) -> None:
        ...

    def dump(self, force: bool = False) -> bytes:
        ...

    @classmethod
    def load(cls: Type[ASN1_VALUE], encoded_data: ByteString, strict: bool = False, **kwargs: Dict[str, _Any]) -> ASN1_VALUE:
        ...

    @property
    def parsed(self) -> _Any:
        ...

    @property
    def native(self) -> _Any:
        ...


class ObjectIdentifier(Asn1Value):
    @property
    def dotted(self) -> str:
        ...


class Null(Asn1Value):
    ...


class Sequence(Asn1Value):
    def __getitem__(self, key: str) -> Asn1Value:
        ...


class UTF8String(Asn1Value):
    ...


class PrintableString(Asn1Value):
    ...

class Choice(Asn1Value):
    @property
    def chosen(self) -> Asn1Value:
        ...

class Integer(Asn1Value):
    def __int__(self) -> int:
        ...

class OctetString(Asn1Value):
    def __bytes__(self) -> bytes:
        ...

class SequenceOf(Asn1Value):
    def __iter__(self) -> Iterator[Asn1Value]:
        ...

class Any(Asn1Value):
    ...
