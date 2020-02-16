"""
Binding to `libsodium <https://libsodium.org/>`_ to use `Ristretto255 <https://ristretto.group/>`_ for group operations.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hmac
from dataclasses import dataclass
from fractions import Fraction
from os import environ
from secrets import randbelow
from typing import TYPE_CHECKING, ByteString, Optional, Union

from asn1crypto.core import Asn1Value, Integer, OctetString

from . import asn1 as _asn1
from .groups import ImageGroup, ImageValue, PgvOrInt, PreGroup, PreGroupValue
from .pvss import Pvss, SystemParameters

if TYPE_CHECKING:  # pragma: no cover
    lazy = property
else:
    from lazy import lazy


# Order of the Ristretto255 group.
group_order = 2 ** 252 + 27742317777372353535851937790883648493


def create_ristretto_255_parameters(pvss: Pvss) -> bytes:
    """
    Create and set Ristretto255 parameters.

    Args:
        pvss: Pvss object with public values

    Returns:
        DER encoded Ristretto255 system parameters.
    """

    result = Ristretto255Parameters.create(pvss, None).der
    pvss.set_params(result)
    return result


class Ristretto255Parameters(SystemParameters):
    ALGO = "ristretto_255"

    @lazy
    def pre_group(self) -> Ristretto255ScalarGroup:
        return Ristretto255ScalarGroup()

    @lazy
    def img_group(self) -> Ristretto255Group:
        return Ristretto255Group(self.pre_group)

    def _make_gen(self, seed: str) -> Ristretto255Point:
        while True:
            dig = hmac.digest(seed.encode(), self.der, "sha512")
            gen = self.img_group.from_hash(dig)

            # Check for neutral elements; we don't want those.
            if gen:
                return gen
            else:  # pragma: no cover
                # Try again with other seed.
                seed += "_"


class _Lib:
    try:
        lib_name = ctypes.util.find_library("sodium")
        if not lib_name:  # pragma: no cover
            raise Exception("libsodium not found")

        lib = ctypes.cdll.LoadLibrary(lib_name)
        if lib.sodium_init() < 0:  # pragma: no cover
            raise Exception("Cannot initialize libsodium")

        # int sodium_memcmp(const void * const b1_, const void * const b2_, size_t len);
        memcmp = lib.sodium_memcmp
        memcmp.restype = ctypes.c_int
        memcmp.argtypes = ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t

        # int sodium_is_zero(const unsigned char *n, const size_t nlen);
        is_zero = lib.sodium_is_zero
        is_zero.restype = ctypes.c_int
        is_zero.argtypes = ctypes.c_char_p, ctypes.c_size_t

        # int crypto_core_ristretto255_is_valid_point(const unsigned char *p);
        point_is_valid = lib.crypto_core_ristretto255_is_valid_point
        point_is_valid.restype = ctypes.c_int
        point_is_valid.argtypes = (ctypes.c_char_p,)

        # void crypto_core_ristretto255_random(unsigned char *p);
        point_random = lib.crypto_core_ristretto255_random
        point_random.restype = None
        point_random.argtypes = (ctypes.c_char_p,)

        # int crypto_core_ristretto255_from_hash(unsigned char *p, const unsigned char *r);
        point_from_hash = lib.crypto_core_ristretto255_from_hash
        point_from_hash.restype = ctypes.c_int
        point_from_hash.argtypes = ctypes.c_char_p, ctypes.c_char_p

        # int crypto_scalarmult_ristretto255(unsigned char *q, const unsigned char *n, const unsigned char *p);
        point_mul = lib.crypto_scalarmult_ristretto255
        point_mul.restype = ctypes.c_int
        point_mul.argtypes = ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p

        # int crypto_scalarmult_ristretto255_base(unsigned char *q, const unsigned char *n);
        point_base_mul = lib.crypto_scalarmult_ristretto255_base
        point_base_mul.restype = ctypes.c_int
        point_base_mul.argtypes = ctypes.c_char_p, ctypes.c_char_p

        # int crypto_core_ristretto255_add(unsigned char *r, const unsigned char *p, const unsigned char *q);
        point_add = lib.crypto_core_ristretto255_add
        point_add.restype = ctypes.c_int
        point_add.argtypes = ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p

        # int crypto_core_ristretto255_sub(unsigned char *r, const unsigned char *p, const unsigned char *q);
        point_sub = lib.crypto_core_ristretto255_sub
        point_sub.restype = ctypes.c_int
        point_sub.argtypes = ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p

        # void crypto_core_ristretto255_scalar_random(unsigned char *r);
        scalar_random = lib.crypto_core_ristretto255_scalar_random
        scalar_random.restype = None
        scalar_random.argtypes = (ctypes.c_char_p,)

        # void crypto_core_ristretto255_scalar_reduce(unsigned char *r, const unsigned char *s);
        scalar_reduce = lib.crypto_core_ristretto255_scalar_reduce
        scalar_reduce.restype = None
        scalar_reduce.argtypes = ctypes.c_char_p, ctypes.c_char_p

        # int crypto_core_ristretto255_scalar_invert(unsigned char *recip, const unsigned char *s);
        scalar_invert = lib.crypto_core_ristretto255_scalar_invert
        scalar_invert.restype = ctypes.c_int
        scalar_invert.argtypes = ctypes.c_char_p, ctypes.c_char_p

        # void crypto_core_ristretto255_scalar_negate(unsigned char *neg, const unsigned char *s);
        scalar_negate = lib.crypto_core_ristretto255_scalar_negate
        scalar_negate.restype = None
        scalar_negate.argtypes = ctypes.c_char_p, ctypes.c_char_p

        # void crypto_core_ristretto255_scalar_complement(unsigned char *comp, const unsigned char *s);
        scalar_complement = lib.crypto_core_ristretto255_scalar_complement
        scalar_complement.restype = None
        scalar_complement.argtypes = ctypes.c_char_p, ctypes.c_char_p

        # void crypto_core_ristretto255_scalar_add(unsigned char *z, const unsigned char *x, const unsigned char *y);
        scalar_add = lib.crypto_core_ristretto255_scalar_add
        scalar_add.restype = None
        scalar_add.argtypes = ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p

        # void crypto_core_ristretto255_scalar_sub(unsigned char *z, const unsigned char *x, const unsigned char *y);
        scalar_sub = lib.crypto_core_ristretto255_scalar_sub
        scalar_sub.restype = None
        scalar_sub.argtypes = ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p

        # void crypto_core_ristretto255_scalar_mul(unsigned char *z, const unsigned char *x, const unsigned char *y);
        scalar_mul = lib.crypto_core_ristretto255_scalar_mul
        scalar_mul.restype = None
        scalar_mul.argtypes = ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p

    except Exception:
        # Work around the fact that libsodium is not installed in the readthedocs build image
        if "READTHEDOCS" not in environ:
            raise


@dataclass(frozen=True, eq=False, repr=False)
class Ristretto255Group(ImageGroup):
    pre_group: Ristretto255ScalarGroup

    def __call__(self, value: Union[Asn1Value]) -> Ristretto255Point:
        """
        Create from serialized buffer, inverse of bytes()
        """
        if not isinstance(value, _asn1.ImgGroupValue):
            raise TypeError(type(value))
        buf = value.chosen
        if not isinstance(buf, OctetString):
            raise TypeError(type(buf))

        res = ctypes.create_string_buffer(bytes(buf), 32)
        if not _Lib.point_is_valid(res):
            raise ValueError("Not a valid point")
        return Ristretto255Point(self, res)

    def random(self) -> Ristretto255Point:
        """
        Generate random element.
        """

        res = ctypes.create_string_buffer(32)
        _Lib.point_random(res)
        return Ristretto255Point(self, res)

    def from_hash(self, value: ByteString) -> Ristretto255Point:
        """
        Generate a point from from up to 64 bytes. Those would usually come out of a hash function.
        """

        buf = ctypes.create_string_buffer(bytes(value), 64)
        res = ctypes.create_string_buffer(32)
        if _Lib.point_from_hash(res, buf) < 0:
            raise Exception("Unknown error")  # pragma: no cover
        return Ristretto255Point(self, res)

    @property
    def len(self) -> int:
        return group_order

    def __repr__(self) -> str:
        return "Ristretto255Group()"


@dataclass(frozen=True, eq=False, repr=False)
class Ristretto255Point(ImageValue):
    group: Ristretto255Group
    _buf: ctypes.Array[ctypes.c_char]

    @lazy
    def asn1(self) -> _asn1.ImgGroupValue:
        return _asn1.ImgGroupValue({"ECPoint": OctetString(bytes(self))})

    def __pow__(
        self, other: Union[PgvOrInt, Fraction], modulo: Optional[int] = None
    ) -> Ristretto255Point:
        """
        Compute self ** other
        """

        if modulo is not None:
            raise TypeError("modulo must be None")

        if isinstance(other, (int, Fraction)):
            buf = self.group.pre_group(other)._buf
        elif isinstance(other, Ristretto255Scalar):
            buf = other._buf
        else:
            return NotImplemented

        res = ctypes.create_string_buffer(32)
        if _Lib.point_mul(res, buf, self._buf) < 0:
            raise ValueError("Zero")
        return Ristretto255Point(self.group, res)

    def __mul__(self, other: ImageValue) -> Ristretto255Point:
        """
        Compute self * other
        """

        if not isinstance(other, Ristretto255Point):
            return NotImplemented

        res = ctypes.create_string_buffer(32)
        if _Lib.point_add(res, self._buf, other._buf) < 0:
            raise ValueError("Encoding error")
        return Ristretto255Point(self.group, res)

    def __floordiv__(self, other: ImageValue) -> Ristretto255Point:
        """
        Compute self / other
        """

        if not isinstance(other, Ristretto255Point):
            return NotImplemented

        res = ctypes.create_string_buffer(32)
        if _Lib.point_sub(res, self._buf, other._buf) < 0:
            raise ValueError("Encoding error")
        return Ristretto255Point(self.group, res)

    def __bytes__(self) -> bytes:
        """
        """

        return bytes(self._buf)

    def __str__(self) -> str:
        """
        """

        return f"Ristretto255Point(0x{bytes(self).hex()})"

    def __repr__(self) -> str:
        """
        """

        return f"Ristretto255Point.from_bytes({bytes(self)!r})"

    def __eq__(self, other: object) -> bool:
        """
        """

        if not isinstance(other, Ristretto255Point):
            return False

        return not _Lib.memcmp(self._buf, other._buf, 32)

    def __bool__(self) -> bool:
        """
        False if this is the neutral element
        """

        return not _Lib.is_zero(self._buf, 32)

    def __hash__(self) -> int:
        return hash(bytes(self._buf))


class Ristretto255ScalarGroup(PreGroup):
    def __call__(self, value: Union[int, Asn1Value, Fraction]) -> Ristretto255Scalar:
        """
        Convert an integer into a group element

        Returns:
            Group element
        """

        if isinstance(value, _asn1.PreGroupValue):
            value = int(value)
            if not 0 <= value < group_order:
                raise ValueError("Not a valid group element")
            res = ctypes.create_string_buffer(value.to_bytes(32, "little"), 32)
            return Ristretto255Scalar(self, res)

        if isinstance(value, int):
            if value < 0:
                neg = True
                value = -value
            else:
                neg = False

            val = ctypes.create_string_buffer(value.to_bytes(64, "little"), 64)
            res = ctypes.create_string_buffer(32)
            _Lib.scalar_reduce(res, val)

            if neg:
                return -Ristretto255Scalar(self, res)
            else:
                return Ristretto255Scalar(self, res)

        if isinstance(value, Fraction):
            return self(value.numerator) * self(value.denominator).inv

        raise TypeError(type(value))

    @property
    def len(self) -> int:
        """
        Get number of elements in this group

        Returns:
            group size
        """

        return group_order

    @property
    def rand(self) -> Ristretto255Scalar:
        """
        Create random element of this group

        Returns:
            Random group element
        """

        value = randbelow(group_order)
        res = ctypes.create_string_buffer(value.to_bytes(32, "little"), 32)
        return Ristretto255Scalar(self, res)

    @property
    def rand_nonzero(self) -> Ristretto255Scalar:
        """
        Create random element of this group, but never the neutral element.

        Returns:
            Random group element
        """

        res = ctypes.create_string_buffer(32)
        _Lib.scalar_random(res)
        return Ristretto255Scalar(self, res)

    def __repr__(self) -> str:
        """
        Outputs a representation of this group.

        Returns:
            Representation of this group
        """

        return "Ristretto255ScalarGroup()"


@dataclass(frozen=True, eq=False, repr=False)
class Ristretto255Scalar(PreGroupValue):
    group: Ristretto255ScalarGroup
    _buf: ctypes.Array[ctypes.c_char]

    def __neg__(self) -> Ristretto255Scalar:
        res = ctypes.create_string_buffer(32)
        _Lib.scalar_negate(res, self._buf)
        return Ristretto255Scalar(self.group, res)

    def __add__(self, other: Union[int, PreGroupValue]) -> Ristretto255Scalar:
        if isinstance(other, int):
            buf = self.group(other)._buf
        elif isinstance(other, Ristretto255Scalar):
            buf = other._buf
        else:
            return NotImplemented

        res = ctypes.create_string_buffer(32)
        _Lib.scalar_add(res, self._buf, buf)
        return Ristretto255Scalar(self.group, res)

    def __sub__(self, other: Union[int, PreGroupValue]) -> Ristretto255Scalar:
        if isinstance(other, int):
            buf = self.group(other)._buf
        elif isinstance(other, Ristretto255Scalar):
            buf = other._buf
        else:
            return NotImplemented

        res = ctypes.create_string_buffer(32)
        _Lib.scalar_sub(res, self._buf, buf)
        return Ristretto255Scalar(self.group, res)

    def __mul__(self, other: Union[int, PreGroupValue]) -> Ristretto255Scalar:
        if isinstance(other, int):
            buf = self.group(other)._buf
        elif isinstance(other, Ristretto255Scalar):
            buf = other._buf
        else:
            return NotImplemented

        res = ctypes.create_string_buffer(32)
        _Lib.scalar_mul(res, self._buf, buf)
        return Ristretto255Scalar(self.group, res)

    @lazy
    def inv(self) -> Ristretto255Scalar:
        res = ctypes.create_string_buffer(32)
        if _Lib.scalar_invert(res, self._buf) < 0:
            raise ValueError("Cannot invert value")

        return Ristretto255Scalar(self.group, res)

    def __eq__(self, other: object) -> bool:
        """
        """

        if not isinstance(other, Ristretto255Scalar):
            return False

        return not _Lib.memcmp(self._buf, other._buf, 32)

    def __bool__(self) -> bool:
        return not _Lib.is_zero(self._buf, 32)

    def __repr__(self) -> str:
        return f"Ristretto255ScalarGroup()({int(self)})"

    def __int__(self) -> int:
        return int.from_bytes(bytes(self._buf), "little")

    def __bytes__(self) -> bytes:
        return bytes(self._buf)

    @lazy
    def asn1(self) -> _asn1.PreGroupValue:
        return _asn1.PreGroupValue(int(self))

    def __hash__(self) -> int:
        return hash(bytes(self))
