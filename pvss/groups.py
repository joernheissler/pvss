"""
Implementation of pre-image and image groups for the group homomorphisms
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from fractions import Fraction
from secrets import randbelow
from typing import Union

from gmpy2 import is_prime

from . import asn1


@dataclass(frozen=True)
class ZqGroup:
    """
    Additive group of integers modulo Sophie Germain prime q
    """

    q: int

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
            value %= self.q
        elif isinstance(value, asn1.PreGroupValue):
            value = int(value)
            if not 0 <= value < self.q:
                raise ValueError("Not a valid group element")
        else:
            raise TypeError(type(value))

        return ZqValue(self, int(value) % self.q)

    @property
    def len(self) -> int:
        """
        Get number of elements in this group

        Returns:
            group size
        """

        return self.q

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
class ZqValue:
    """
    Elements of ZqGroup
    """

    group: ZqGroup
    value: int

    def __int__(self):
        """
        Implement int(a)

        Returns:
            value
        """

        return self.value

    def __neg__(self) -> ZqValue:
        """
        Implement -a

        Returns:
            inverse value
        """

        return self.group(-self.value)

    def __add__(self, other: ZqOrInt) -> ZqValue:
        """
        Implement a + b

        Params:
            other: Second operand

        Returns:
            Sum of `self` and `other`
        """

        if isinstance(other, int):
            return self.group(self.value + other)

        if isinstance(other, ZqValue):
            if self.group is not other.group:
                return NotImplemented

            return self.group(self.value + other.value)

        return NotImplemented

    def __radd__(self, other: ZqOrInt) -> ZqValue:
        """
        Implement b + a

        Params:
            other: First operand

        Returns:
            Sum of `other` and `self`
        """

        return self.__add__(other)

    def __mul__(self, other: Union[ZqOrInt, Fraction]) -> ZqValue:
        """
        Implement a * b

        Params:
            other: Second operand

        Returns:
            Product of `self` and `other`
        """

        if isinstance(other, int):
            return self.group(self.value * other)

        if isinstance(other, ZqValue):
            if self.group is not other.group:
                return NotImplemented

            return self.group(self.value * other.value)

        if isinstance(other, Fraction):
            if other.denominator == 1:
                return self.group(self.value * other.numerator)

            return self.group(
                self.value * other.numerator * pow(other.denominator, -1, self.group.q)
            )

        return NotImplemented

    def __rmul__(self, other: Union[ZqOrInt, Fraction]) -> ZqValue:
        """
        Implement b * a

        Params:
            other: First operand

        Returns:
            Product of `other` and `self`
        """

        return self.__mul__(other)

    def __pow__(self, other: int, modulo: int = None) -> ZqValue:
        """
        Implement a ** b and pow(a, b)

        Params:
            other: exponent
            modulo: Not supported, must be None

        Returns:
            `self` raised to the power of `other`
        """

        if modulo is not None:
            raise Exception("Modulo not supported")

        if not isinstance(other, int):
            return NotImplemented

        return self.group(pow(self.value, other, self.group.q))

    def __repr__(self) -> str:
        """
        Outputs a representation of this value.

        Returns:
            Representation of this value
        """

        return f"{self.group}({self.value})"


# Operations in ZqValue take ZqValue and int as operands.
ZqOrInt = Union[ZqValue, int]


@dataclass(frozen=True)
class ImageGroup(ABC):
    """
    Abstract image group, can e.g. be some elliptic curve or quadratic residues modulo p
    """

    @abstractmethod
    def __call__(self, value: Union[asn1.ImgGroupValue]) -> ImageValue:
        """
        Create element of this group
        """

    @property
    @abstractmethod
    def len(self) -> int:
        """
        Get number of elements in this group

        Returns:
            group size
        """

    @abstractmethod
    def __repr__(self) -> str:
        """
        Outputs a representation of this group.

        Returns:
            Representation of this group
        """


@dataclass(frozen=True)
class ImageValue(ABC):
    """
    Abstract image value, e.g. a curve point or a quadratic residue modulo p
    """

    group: ImageGroup

    @property
    @abstractmethod
    def asn1(self) -> asn1.ImgGroupValue:
        """
        Convert value to an ASN.1 type so it can be serialized to DER.

        Returns:
            Value converted to an ASN.1 value
        """

    @abstractmethod
    def __mul__(self, other: ImageValue) -> ImageValue:
        """
        Implement the group operation a * b.

        Params:
            other: Second operand

        Returns:
            Product of `self` and `other`
        """

    @abstractmethod
    def __pow__(self, other: Union[int, ZqValue], modulo: int = None) -> ImageValue:
        """
        Implement a ** b and pow(a, b), i.e. the repeated application of the group operation to `a`.

        Params:
            other: exponent
            modulo: Not supported, must be None

        Returns:
            `self` raised to the power of `other`
        """
