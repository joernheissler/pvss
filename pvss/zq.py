"""
"""

from __future__ import annotations

from dataclasses import dataclass
from os import environ
from secrets import randbelow
from typing import TYPE_CHECKING, Any, Union, cast

from asn1crypto.core import Asn1Value

try:
    from gmpy2 import invert, is_prime, mpz
except ImportError:
    # Work around the fact that gmpy2 is not installed in the readthedocs build image
    if "READTHEDOCS" not in environ:
        raise

from . import asn1
from .groups import PgvOrInt, PreGroup, PreGroupValue

if TYPE_CHECKING:  # pragma: no cover
    lazy = property
else:
    from lazy import lazy


@dataclass(frozen=True)
class ZqGroup(PreGroup):
    """
    Additive group of integers modulo Sophie Germain prime q
    """

    q: mpz

    def __post_init__(self) -> None:
        """
        Ensure that q and 2q+1 are prime.
        """

        if self.q < 0:
            raise ValueError("q is negative")

        if not is_prime(self.q):
            raise ValueError("q not prime")

        if not is_prime(self.q * 2 + 1):
            raise ValueError("2q + 1 not prime")

    def __call__(self, value: Union[int, Asn1Value]) -> ZqValue:
        """
        Convert an integer into a group element

        Returns:
            Group element
        """

        if isinstance(value, int):
            return ZqValue(self, value % self.q)

        if isinstance(value, asn1.PreGroupValue):
            mpz_value = mpz(int(value))
            if not 0 <= mpz_value < self.q:
                raise ValueError("Not a valid group element")
            return ZqValue(self, mpz_value)

        raise TypeError(f"Type not supported: {type(value)}")

    @property
    def len(self) -> int:
        """
        Get number of elements in this group

        Returns:
            group size
        """

        return int(self.q)

    @property
    def rand(self) -> ZqValue:
        """
        Create random element of this group

        Returns:
            Random group element
        """

        return self(randbelow(int(self.q)))

    @property
    def rand_nonzero(self) -> ZqValue:
        """
        Create random element of this group, but never the neutral element.

        Returns:
            Random group element
        """

        return self(1 + randbelow(int(self.q - 1)))

    def __repr__(self) -> str:
        """
        Outputs a representation of this group.

        Returns:
            Representation of this group
        """

        return f"ZqGroup({self.q})"


@dataclass(frozen=True, eq=False)
class ZqValue(PreGroupValue):
    """
    Elements of ZqGroup
    """

    group: ZqGroup
    _value: mpz

    def __int__(self) -> int:
        """
        Implement int(a)

        Returns:
            value
        """

        return int(self._value)

    def __neg__(self) -> ZqValue:
        """
        Implement -a

        Returns:
            inverse value
        """

        return ZqValue(self.group, -self._value % self.group.q)

    def __add__(self, other: PgvOrInt) -> ZqValue:
        """
        Implement a + b

        Args:
            other: Second operand

        Returns:
            Sum of `self` and `other`
        """

        if isinstance(other, int):
            return ZqValue(self.group, (self._value + other) % self.group.q)

        if isinstance(other, ZqValue):
            if self.group is not other.group:
                raise TypeError("Group mismatch")

            return ZqValue(self.group, (self._value + other._value) % self.group.q)

        return NotImplemented

    def __mul__(self, other: PgvOrInt) -> ZqValue:
        """
        Implement a * b

        Args:
            other: Second operand

        Returns:
            Product of `self` and `other`
        """

        if isinstance(other, int):
            return ZqValue(self.group, self._value * other % self.group.q)

        if isinstance(other, ZqValue):
            if self.group is not other.group:
                raise TypeError("Group mismatch")

            return ZqValue(self.group, self._value * other._value % self.group.q)

        return NotImplemented

    @property
    def inv(self) -> ZqValue:
        """
        Implement multiplicative inverse such that inv(x) * x == 1

        Returns:
            Multiplicative inverse of `self`
        """
        return ZqValue(self.group, invert(self._value, self.group.q))

    def __repr__(self) -> str:
        """
        Outputs a representation of this value.

        Returns:
            Representation of this value
        """

        return f"{self.group}({self._value})"

    @lazy
    def asn1(self) -> asn1.PreGroupValue:
        """
        Convert value to an ASN.1 type so it can be serialized to DER.

        Returns:
            Value converted to an ASN.1 value
        """
        return asn1.PreGroupValue(int(self._value))

    def __eq__(self, other: Any) -> bool:
        """
        """

        if isinstance(other, ZqValue):
            # "is not" is by intention to force usage of the identical group.
            if self.group is not other.group:
                return False

            return self._value == other._value

        return self._value == cast(int, other)
