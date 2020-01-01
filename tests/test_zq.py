from typing import cast

import pytest
from gmpy2 import mpz
from pvss.asn1 import PreGroupValue
from pvss.zq import ZqGroup


def test_init() -> None:
    with pytest.raises(ValueError, match="q is negative"):
        ZqGroup(mpz(-13))

    with pytest.raises(ValueError, match="q not prime"):
        ZqGroup(mpz(12))

    with pytest.raises(ValueError, match=r"2q \+ 1 not prime"):
        ZqGroup(mpz(13))


def test_call() -> None:
    grp = ZqGroup(mpz(53))
    assert grp(20) == 20
    assert grp(200) == 41
    assert grp(PreGroupValue(20)) == 20

    with pytest.raises(ValueError, match="Not a valid group element"):
        grp(PreGroupValue(200))

    with pytest.raises(TypeError):
        grp(cast(int, "twenty"))


def test_len() -> None:
    assert ZqGroup(mpz(53)).len == 53


def test_rand() -> None:
    tmp = {int(ZqGroup(mpz(2)).rand) for __ in range(100)}
    assert 0 <= min(tmp) <= max(tmp) <= 1


def test_rand_nonzero() -> None:
    tmp = {int(ZqGroup(mpz(2)).rand_nonzero) for __ in range(100)}
    assert tmp == {1}


def test_repr() -> None:
    assert repr(ZqGroup(mpz(53))) == "ZqGroup(53)"


def test_value() -> None:
    grp = ZqGroup(mpz(53))
    assert grp(10) + grp(20) == grp(30)
    assert 20 + grp(10) == grp(30)
    assert grp(40) + grp(50) == grp(37)
    assert grp(40) + 50 == grp(37)
    assert ZqGroup(mpz(53))(20) != grp(20)

    with pytest.raises(TypeError, match="Group mismatch"):
        grp(10) + ZqGroup(mpz(53))(10)

    with pytest.raises(TypeError):
        grp(10) + cast(int, "twenty")

    assert -grp(10) == grp(43)
    assert grp(10) * grp(22) == grp(8)
    assert 22 * grp(10) == grp(8)
    with pytest.raises(TypeError, match="Group mismatch"):
        grp(10) * ZqGroup(mpz(53))(10)
    with pytest.raises(TypeError):
        grp(10) * cast(int, "twentytwo")

    # 1 = 16 * 10 - 3 * 53
    assert 16 == grp(10).inv
    assert repr(grp(10)) == "ZqGroup(53)(10)"
    assert grp(10).asn1.dump() == b"\x02\x01\x0a"
