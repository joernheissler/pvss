"""
Quadratic residues modulo safe prime p
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from fractions import Fraction
from os import environ
from typing import TYPE_CHECKING, ByteString, Optional, Union, cast

from asn1crypto.algos import DHParameters
from asn1crypto.core import Asn1Value, Integer
from asn1crypto.pem import unarmor

try:
    from gmpy2 import invert, is_prime, legendre, mpz, powmod
except ImportError:
    # Work around the fact that gmpy2 is not installed in the readthedocs build image
    if "READTHEDOCS" not in environ:
        raise
else:
    # Will be fixed by gmpy2 2.1
    mpz_type = mpz if isinstance(mpz, type) else type(mpz(0))

from .asn1 import ImgGroupValue
from .groups import ImageGroup, ImageValue, PgvOrInt
from .pvss import Pvss, SystemParameters
from .zq import ZqGroup, ZqValue

if TYPE_CHECKING:  # pragma: no cover
    lazy = property
else:
    from lazy import lazy


def create_qr_params(pvss: Pvss, params: Union[int, str, ByteString]) -> bytes:
    """
    Create and set QR parameters.

    If params is str or a ByteString, assume it's a diffie-hellman parameter file
    such as created by "openssl dhparam 4096", either DER or PEM encoded.

    Args:
        pvss: Pvss object with public values
        params: if int, must be a safe prime, otherwise must be a DH params file with a safe prime.

    Returns:
        DER encoded QR system parameters.
    """

    if not isinstance(params, int):
        if isinstance(params, str):
            params = params.encode()

        if params[0] != 0x30:
            # DER encoding of "Sequence" starts with 0x30. So it's probably PEM.
            params = unarmor(bytes(params))[2]

        params = int(cast(Integer, DHParameters.load(bytes(params))["p"]))

    result = QrParameters.create(pvss, params).der
    pvss.set_params(result)
    return result


class QrParameters(SystemParameters):
    """
    Quadratic residues modulo p.
    """

    ALGO = "qr_mod_p"

    @lazy
    def pre_group(self) -> ZqGroup:
        return ZqGroup(mpz(self.img_group.len))

    @lazy
    def img_group(self) -> QrGroup:
        """
        Create image group singleton
        """

        return QrGroup(mpz(int(cast(Integer, self.asn1["parameters"]))))

    def _make_gen(self, seed: str) -> QrValue:
        """
        Deterministic pseudo-random function to generate a group element.
        """
        key = seed.encode()
        p = self.img_group.p
        bits = p.bit_length() * 2

        dig = self.der
        tmp = bytearray()

        while len(tmp) * 8 < bits:
            dig = hmac.digest(key, dig, "sha256")
            tmp.extend(dig)

        # Square to get a quadratic residue
        value = powmod(int.from_bytes(tmp, "big"), 2, p)

        # Check for bad value. 0 is no group element at all. 1 is the neutral element.
        if value in {0, 1}:
            # Try again with new seed. This happening is extremely unlikely.
            return self._make_gen(seed + "_")

        return self.img_group(value)


@dataclass(frozen=True)
class QrGroup(ImageGroup):
    """
    Multiplicative group of Quadratic Residues modulo safe prime p
    """

    p: mpz

    def __post_init__(self) -> None:
        if not is_prime(self.p):
            raise ValueError("p not prime")

        if not is_prime(self.len):
            raise ValueError("(p - 1) / 2 not prime")

    def __call__(self, value: Union[int, mpz, Integer, Asn1Value]) -> QrValue:
        if isinstance(value, (int, mpz_type)):
            value %= self.p
            if value == 0:
                raise ValueError("0 not in group")
            return QrValue(self, value)

        if isinstance(value, ImgGroupValue):
            value = value.chosen

        if not isinstance(value, Integer):
            raise TypeError(type(value))

        value = mpz(int(value))

        if not 1 <= value < self.p:
            raise ValueError("Not a valid group element")

        if legendre(value, self.p) != 1:
            raise ValueError("Not a valid group element")

        return QrValue(self, value)

    @lazy
    def len(self) -> int:
        return int(self.p // 2)

    def __repr__(self) -> str:
        """
        Outputs a representation of this group.

        Returns:
            Representation of this group
        """

        return f"QrGroup({self.p})"


@dataclass(frozen=True)
class QrValue(ImageValue):
    """
    Elements of QrGroup. The value is always in [1, p).
    """

    group: QrGroup
    value: mpz

    @property
    def asn1(self) -> ImgGroupValue:
        """
        Convert to ASN.1 Integer type
        """

        return ImgGroupValue({"QrValue": Integer(int(self))})

    def __int__(self) -> int:
        """
        Returns:
            Value of self as a native python integer
        """
        return int(self.value)

    def __mul__(self, other: ImageValue) -> QrValue:
        """
        Implement the group operation a * b.

        Args:
            other: Second operand

        Returns:
            Product of `self` and `other`
        """

        if not isinstance(other, QrValue):
            return NotImplemented

        return self.group(self.value * other.value)

    def __pow__(
        self, other: Union[PgvOrInt, Fraction], modulo: Optional[int] = None
    ) -> QrValue:
        """
        Implement a ** b and pow(a, b).
        If b is a Fraction c/d, compute a ** (c * (d^-1))

        Args:
            other: exponent
            modulo: Not supported, must be None

        Returns:
            `self` raised to the power of `other`
        """

        if modulo is not None:
            raise Exception("Modulo not supported")

        if isinstance(other, int):
            return self.group(powmod(self.value, other, self.group.p))

        if isinstance(other, ZqValue):
            if other.group.len != self.group.len:
                raise TypeError("incompatible groups")
            return self.group(powmod(self.value, int(other), self.group.p))

        if isinstance(other, Fraction):
            tmp = powmod(self.value, other.numerator, self.group.p)

            if other.denominator != 1:
                tmp = powmod(tmp, invert(other.denominator, self.group.len), self.group.p)
            return self.group(tmp)

        return NotImplemented

    def __repr__(self) -> str:
        """
        Outputs a representation of this value.

        Returns:
            Representation of this value
        """

        return f"{self.group}({int(self)})"
