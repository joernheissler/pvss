from fractions import Fraction
from typing import cast

import pytest
from asn1crypto.core import Integer
from gmpy2 import mpz
from pvss.asn1 import ImgGroupValue
from pvss.pvss import Pvss
from pvss.qr import QrGroup, QrParameters, QrValue, create_qr_params
from pvss.zq import ZqGroup


def test_params() -> None:
    der = bytes.fromhex("3011060c2b0601040183ae0001000100020117")
    params_pem = "foobar\n-----BEGIN DH PARAMETERS-----\nMAYCARcCAQI=\n-----END DH PARAMETERS-----\nspam\n"

    pvss = Pvss()
    assert der == create_qr_params(pvss, 23)

    pvss = Pvss()
    assert der == create_qr_params(pvss, b"\x30\x06\x02\x01\x17\x02\x01\x02")

    pvss = Pvss()
    assert der == create_qr_params(pvss, params_pem)

    pvss = Pvss()
    assert der == create_qr_params(pvss, params_pem.encode())


def test_gen() -> None:
    params = QrParameters.create(Pvss(), 23)
    assert int(params._make_gen("a")) == 9

    # hits 1
    assert int(params._make_gen("j")) == 18
    assert params._make_gen("j") == params._make_gen("j_")

    # hits 0
    assert int(params._make_gen("al")) == 13
    assert params._make_gen("al") == params._make_gen("al_")


def test_grp_init() -> None:
    QrGroup(mpz(23))

    with pytest.raises(ValueError, match="p not prime"):
        QrGroup(mpz(20))

    with pytest.raises(ValueError, match=r"\(p - 1\) / 2 not prime"):
        QrGroup(mpz(17))


def test_grp_call() -> None:
    grp = QrGroup(mpz(23))

    assert int(grp(1)) == 1
    assert int(grp(81)) == 12
    assert int(grp(ImgGroupValue.load(b"\02\x01\x0c"))) == 12
    assert int(grp(Integer(12))) == 12

    with pytest.raises(ValueError, match="0 not in group"):
        grp(46)

    with pytest.raises(TypeError):
        grp(ImgGroupValue.load(b"\x04\x01\x0c"))

    with pytest.raises(ValueError, match="Not a valid group element"):
        grp(ImgGroupValue.load(b"\x02\x01\x23"))

    with pytest.raises(ValueError, match="Not a valid group element"):
        grp(ImgGroupValue.load(b"\x02\x01\x05"))


def test_grp_len() -> None:
    assert QrGroup(mpz(23)).len == 11


def test_grp_repr() -> None:
    assert repr(QrGroup(mpz(23))) == "QrGroup(23)"


def test_value_asn1() -> None:
    assert QrGroup(mpz(23))(12).asn1.dump() == b"\02\x01\x0c"


def test_value_mul() -> None:
    grp = QrGroup(mpz(23))
    assert grp(12) * grp(2) == grp(1)
    assert grp(12) * grp(16) == grp(8)
    assert grp(1) * grp(16) == grp(16)
    assert grp(13) * grp(16) == grp(1)

    with pytest.raises(TypeError):
        grp(1) * cast(QrValue, 1)


def test_value_pow() -> None:
    grp = QrGroup(mpz(23))
    assert grp(13) ** -1 == grp(16)
    assert grp(13) ** ZqGroup(mpz(11))(5) == grp(4)
    assert ((grp(13) ** Fraction(3, 4)) ** Fraction(4, 1)) ** Fraction(1, 3) == grp(13)

    with pytest.raises(TypeError, match="incompatible groups"):
        grp(13) ** ZqGroup(mpz(29))(16)

    with pytest.raises(Exception, match="Modulo not supported"):
        pow(cast(int, grp(13)), -1, 123)

    with pytest.raises(TypeError):
        grp(13) ** cast(int, "two")


def test_value_repr() -> None:
    assert repr(QrGroup(mpz(23))(13)) == "QrGroup(23)(13)"
