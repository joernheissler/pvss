import ctypes
from fractions import Fraction
from hashlib import sha512
from typing import cast

import pytest
from asn1crypto.core import UTF8String
from pvss.asn1 import ImgGroupValue, PreGroupValue
from pvss.pvss import Pvss
from pvss.ristretto_255 import (
    Ristretto255Group,
    Ristretto255Parameters,
    Ristretto255Point,
    Ristretto255ScalarGroup,
    create_ristretto_255_parameters,
)

order = 2 ** 252 + 27742317777372353535851937790883648493


def test_create_parameters() -> None:
    pvss = Pvss()
    params = Ristretto255Parameters.from_der(pvss, create_ristretto_255_parameters(pvss))
    assert params._make_gen("x") != params._make_gen("y")


def test_scalar_call() -> None:
    grp = Ristretto255ScalarGroup()
    assert int(grp(PreGroupValue.load(b"\x02\x01\x20"))) == 32

    with pytest.raises(ValueError, match="Not a valid group element"):
        # negative value
        grp(PreGroupValue.load(b"\x02\x01\x90"))

    with pytest.raises(ValueError, match="Not a valid group element"):
        # huge value
        grp(PreGroupValue.load(b"\x02\x28" + b"\x50" * 0x28))

    assert int(grp(-123)) == order - 123
    assert int(grp(123 + order * 123456789)) == 123

    assert grp(Fraction(7, 11)) * grp(Fraction(11, 7)) == grp(1)

    with pytest.raises(TypeError):
        grp(cast(int, "a dozen"))


def test_scalar_group() -> None:
    grp = Ristretto255ScalarGroup()
    assert grp.len == order

    assert len({grp.rand for __ in range(1000)}) >= 997

    values = set()
    for __ in range(1000):
        value = grp.rand_nonzero
        assert int(value) > 0
        values.add(value)
    assert len(values) >= 997

    assert repr(grp) == "Ristretto255ScalarGroup()"


def test_scalar_point() -> None:
    grp = Ristretto255ScalarGroup()

    a = grp.rand_nonzero
    b = grp.rand_nonzero

    assert int(a + -a) == 0
    assert int(a + 42) == (int(a) + 42) % order

    with pytest.raises(TypeError):
        a + cast(int, "ten")

    assert int(a - b) == (int(a) - int(b)) % order
    assert a - int(b) == a - b

    with pytest.raises(TypeError):
        a - cast(int, "ten")

    assert int(a * b) == int(a) * int(b) % order
    assert a * int(b) == a * b

    with pytest.raises(TypeError):
        a * cast(int, "ten")

    assert (a * b).inv == a.inv * b.inv
    with pytest.raises(ValueError, match="Cannot invert value"):
        grp(0).inv

    assert a != "a"

    assert a
    assert not grp(0)

    assert repr(grp(123)) == "Ristretto255ScalarGroup()(123)"

    assert grp(1234).asn1.dump() == b"\x02\x02\x04\xd2"


def test_group_call() -> None:
    grp = Ristretto255Group(Ristretto255ScalarGroup())

    with pytest.raises(TypeError):
        grp(UTF8String("three"))

    with pytest.raises(TypeError):
        grp(ImgGroupValue.load(b"\x02\x01\x34"))

    with pytest.raises(ValueError, match="Not a valid point"):
        grp(ImgGroupValue.load(b"\x04\x20" + bytes(31) + b"\x01"))

    four = b"\x04" + bytes(31)
    assert bytes(grp(ImgGroupValue.load(b"\x04\x20" + four))) == four


def test_group() -> None:
    grp = Ristretto255Group(Ristretto255ScalarGroup())

    assert len({grp.random() for __ in range(1000)}) >= 997

    # all zero maps to zero element
    assert bytes(grp.from_hash(bytes(64))) == bytes(32)

    # Test vector from https://ristretto.group/test_vectors/ristretto255.html
    assert bytes(
        grp.from_hash(
            sha512(b"Ristretto is traditionally a short shot of espresso coffee").digest()
        )
    ) == bytes.fromhex("3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46")

    assert grp.len == order

    assert repr(grp) == "Ristretto255Group()"


def test_group_point() -> None:
    pre = Ristretto255ScalarGroup()
    grp = Ristretto255Group(pre)

    a = grp.random()
    b = grp.random()
    c = grp.random()

    assert a.asn1.dump() == b"\x04\x20" + bytes(a)

    with pytest.raises(TypeError, match="modulo must be None"):
        pow(cast(int, a), 234, 567)

    assert ((a ** 3) ** Fraction(1, 15)) ** pre(5) == a

    with pytest.raises(TypeError):
        a ** cast(int, "five")

    with pytest.raises(ValueError, match="Zero"):
        a ** 0

    assert a * b // c // b * c == a

    bad_point = Ristretto255Point(grp, ctypes.create_string_buffer(b"\x01" + bytes(31), 32))

    with pytest.raises(TypeError):
        a * cast(Ristretto255Point, 10)
    with pytest.raises(ValueError, match="Encoding error"):
        a * bad_point

    with pytest.raises(TypeError):
        a // cast(Ristretto255Point, 10)
    with pytest.raises(ValueError, match="Encoding error"):
        a // bad_point

    assert str(a).startswith("Ristretto255Point(0x")
    assert repr(a).startswith("Ristretto255Point.from_bytes(")
    assert a != "a"
