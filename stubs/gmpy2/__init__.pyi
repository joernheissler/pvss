from __future__ import annotations
from typing import Union, Any


class mpz(object):
    def __init__(self, x: _mpz) -> None:
        ...

    def __add__(self, other: _mpz) -> mpz:
        ...

    def __sub__(self, other: _mpz) -> mpz:
        ...

    def __mul__(self, other: _mpz) -> mpz:
        ...

    def __floordiv__(self, other: _mpz) -> mpz:
        ...

    def __mod__(self, other: _mpz) -> mpz:
        ...

    def __rmod__(self, other: _mpz) -> mpz:
        ...

    def __neg__(self) -> mpz:
        ...

    def __int__(self) -> int:
        ...

    def __ge__(self, other: Any) -> bool:
        ...

    def __lt__(self, other: Any) -> bool:
        ...

    def bit_length(self) -> int:
        ...

_mpz = Union[mpz, int]

def invert(x: _mpz, m: _mpz) -> mpz:
    ...


def is_prime(x: _mpz, n: int = 25) -> bool:
    ...


def legendre(x: _mpz, y: _mpz) -> mpz:
    ...


def powmod(x: _mpz, y: _mpz, m: _mpz) -> mpz:
    ...
