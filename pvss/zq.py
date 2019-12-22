"""
"""

from __future__ import annotations

from dataclasses import dataclass
from secrets import randbelow

from gmpy2 import invert, is_prime, mpz
from lazy import lazy

from . import asn1
from .groups import PgvOrInt, PreGroup, PreGroupValue


@dataclass(frozen=True)
class ZqGroup(PreGroup):
    """
    Additive group of integers modulo Sophie Germain prime q
    """

    q: mpz

    def __post_init__(self):
        """
        Ensure that q and 2q+1 are prime.
        """

        if not is_prime(self.q):
            raise ValueError("q not prime")

        if not is_prime(self.q * 2 + 1):
            raise ValueError("2q + 1 not prime")

    def __call__(self, value: Union[int, asn1.PreGroupValue]) -> ZqValue:
        """
        Convert an integer into a group element

        Returns:
            Group element
        """

        if isinstance(value, int):
            return ZqValue(self, value % self.q)

        if isinstance(value, asn1.PreGroupValue):
            value = mpz(value)
            if not 0 <= value < self.q:
                raise ValueError("Not a valid group element")
            return ZqValue(self, value)

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

        return self(randbelow(self.q))

    @property
    def rand_nonzero(self) -> ZqValue:
        """
        Create random element of this group, but never the neutral element.

        Returns:
            Random group element
        """

        return self(1 + randbelow(self.q - 1))

    def __repr__(self) -> str:
        """
        Outputs a representation of this group.

        Returns:
            Representation of this group
        """

        return f"ZqGroup({self.q})"


@dataclass(frozen=True)
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

        Params:
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

        Params:
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
