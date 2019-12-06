"""
Implementation of some groups
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, TypeVar, Union
from random import randrange as rand
from fractions import Fraction

from gmpy2 import powmod


@dataclass(frozen=True)
class Zq:
    """
    Additive group of integers modulo Sophie Germain prime q
    """

    q: int

    @classmethod
    def load(cls, q: int) -> Zq:
        return cls(int(q))

    def __call__(self, value: int) -> ZqValue:
        return ZqValue(self, int(value) % self.q)

    @property
    def len(self) -> int:
        return self.q

    @property
    def rand(self) -> ZqValue:
        return self(rand(self.q))


@dataclass(frozen=True)
class ZqValue:
    """
    Elements of Zq
    """

    group: Zq
    value: int

    def __int__(self):
        return self.value

    def __neg__(self) -> ZqValue:
        return self.group(-self.value)

    def __add__(self, other: ZqOrInt) -> ZqValue:
        if isinstance(other, int):
            return self.group(self.value + other)

        if isinstance(other, ZqValue):
            if self.group is not other.group:
                return NotImplemented

            return self.group(self.value + other.value)

        return NotImplemented

    def __radd__(self, other: ZqOrInt) -> ZqValue:
        return self.__add__(other)

    def __mul__(self, other: ZqOrInt) -> ZqValue:
        if isinstance(other, int):
            return self.group(self.value * other)

        if isinstance(other, ZqValue):
            if self.group is not other.group:
                return NotImplemented

            return self.group(self.value * other.value)

        if isinstance(other, Fraction):
            if other.denominator == 1:
                return self.group(self.value * other.numerator)

            return self.group(self.value * other.numerator * pow(other.denominator, -1, self.group.q))

        return NotImplemented

    def __rmul__(self, other: ZqOrInt) -> ZqValue:
        return self.__mul__(other)

    def __pow__(self, other: int, modulo: Optional[int] = None) -> ZqValue:
        if not isinstance(other, int):
            return NotImplemented
        if modulo is not None:
            return NotImplemented
        return self.group(powmod(self.value, other, self.group.q))
        # return self.group(pow(self.value, other, self.group.q))

    def __repr__(self) -> str:
        return f"Zq({self.value}, {self.group.q})"


ZqOrInt = Union[ZqValue, int, Fraction]

@dataclass(frozen=True)
class MultGroup:
    @property
    @abstractmethod
    def neutral(self) -> MultValue:
        """
        Neutral element of group
        """



@dataclass(frozen=True)
class MultValue(ABC):
    """
    """

    group: Qr

#   def __pow__(self: MultValue, other: Union[int, ZqValue]) -> MultValue:
#       if isinstance(other, int):
#           power = other
#       elif isinstance(other, ZqValue):
#           if other.group.len != self.group.len:
#               raise TypeError("incompatible groups")
#           power = other.value
#       else:
#           return NotImplemented

#       result = self.group.neutral
#       if power < 0:
#           power = -power
#           tmp = -self
#       else:
#           tmp = self

#       while power:
#           if power % 2:
#               result *= tmp
#           power >>= 1
#           tmp *= tmp

#       return result


@dataclass(frozen=True)
class Qr(MultGroup):
    """
    Multiplicative group of Quadratic Residues modulo safe prime p
    """

    p: int

    @classmethod
    def load(cls, p: int) -> Qr:
        return cls(int(p))

    @property
    def neutral(self) -> QrValue:
        return self(1)

    def __call__(self, value: int) -> QrValue:
        value = int(value) % self.p
        if value == 0:
            raise ValueError("0 not in group")
        return QrValue(self, value)

    @property
    def len(self) -> int:
        return self.p // 2


@dataclass(frozen=True)
class QrValue(MultValue):
    """
    Elements of Qr
    """

    value: int

    def __int__(self):
        return self.value

    def __mul__(self, other: QrValue) -> QrValue:
        return self.group(self.value * other.value)

    def __rmul__(self, other: QrValue) -> QrValue:
        return self.__mul__(other)

    def __repr__(self) -> str:
        return f"Qr({self.value}, {self.group.p})"

    def __neg__(self) -> QrValue:
        return self.group(pow(self.value, -1, self.group.p))

    def __pow__(self: QrValue, other: ZqOrInt) -> QrValue:
        if isinstance(other, int):
            return self.group(powmod(self.value, other, self.group.p))

        if isinstance(other, ZqValue):
            if other.group.len != self.group.len:
                raise TypeError("incompatible groups")
            return self.group(powmod(self.value, other.value, self.group.p))

        if isinstance(other, Fraction):
            if other.denominator == 1:
                return self.group(powmod(self.value, other.numerator, self.group.p))

            tmp = powmod(self.value, other.numerator, self.group.p)
            tmp = powmod(tmp, pow(other.denominator, -1, self.group.len), self.group.p)
            return self.group(tmp)

        return NotImplemented
