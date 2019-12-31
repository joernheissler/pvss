from typing import Dict

from pvss.pvss import Pvss, Poly, zip_strict, prod, PrivateKey
from pvss.zq import ZqGroup
from pvss.qr import create_qr_params, QrParameters
from gmpy2 import mpz

import pytest


def test_zip_strict() -> None:
    assert list(zip_strict("foo", "bar", "baz")) == [('f','b','b'), ('o', 'a', 'a'), ('o', 'r', 'z')]

    with pytest.raises(ValueError, match="Not all iters finished at the same time"):
        list(zip_strict("foo", "baaar", "baz"))

def test_poly() -> None:
    grp = ZqGroup(mpz(11))

    # p(x) = 2 + 7x + 0x² + 1x³
    p = Poly([grp(2), grp(7), grp(0), grp(1)], grp(0))

    assert len(p) == 4
    assert p[0] == grp(2)
    assert p[2] == grp(0)

    assert p(5) == grp(2 + 35 + 0 + 125)

    assert repr(p) == 'Poly([ZqGroup(11)(2), ZqGroup(11)(7), ZqGroup(11)(0), ZqGroup(11)(1)])'


def test_prod() -> None:
    assert prod([10, 20, 30]) == 6000
    assert prod([4, 5], 6) == 120
    assert prod([], 6) == 6

    with pytest.raises(TypeError):
        prod([])


def test_pvss() -> None:
    pvss = Pvss()
    params = create_qr_params(pvss, 23)
    assert params == bytes.fromhex('3011060c2b0601040183ae0001000100020117')
    pvss.params = params  # type: ignore

    # Luckily no two generators are the same in this tiny group.
    assert len({pvss.params.g, pvss.params.h, pvss.params.G, pvss.params.H}) == 4

    keys: Dict[str, bytes] = {}
    for name in ["Alice", "Boris", "Chris"]:
        # keys are created by random and we've got lots of duplicates. Try again.
        while True:
            try:
                priv, pub = pvss.create_keypair(name)
                pvss.add_shareholder_public_key(pub)
                break
            except ValueError as ex:  # pragma: no cover
                if 'Duplicate public key' not in str(ex):
                    raise
        keys[name] = priv

    with pytest.raises(ValueError, match="Duplicate name:"):
        pvss.add_shareholder_public_key(pub)

    with pytest.raises(ValueError):
        pvss.create_keypair("")

    assert PrivateKey.from_der(pvss, keys["Alice"]) == PrivateKey.from_der(pvss, keys["Alice"])
    assert PrivateKey.from_der(pvss, keys["Alice"]) != PrivateKey.from_der(pvss, keys["Boris"])
    assert PrivateKey.from_der(pvss, keys["Alice"]) != "Alice"

    while True:
        priv, pub = pvss.create_keypair("David")
        if priv in keys.values():
            with pytest.raises(ValueError, match="Duplicate public key"):
                pvss.add_shareholder_public_key(pub)
            break
        else:  # pragma: no cover
            pass

    secret0, shares = pvss.share_secret(2)
    with pytest.raises(ValueError, match="could not compute same challenge"):
        pvss.shares = shares[:-1] + bytes(((shares[-1] + 1) % 256,))  # type: ignore
    pvss.shares = shares  # type: ignore

    assert secret0[0] == 48
    assert shares[0] == 48

    recp_priv, recp_pub = pvss.create_keypair("Recipient")
    pvss.recipient_public_key = recp_pub  # type: ignore

    pvss.add_reencrypted_share(pvss.reencrypt_share(keys["Alice"]))
    with pytest.raises(Exception, match="Need at least 2 shares, only got 1"):
        pvss.reconstruct_secret(recp_priv)
    chris_share = pvss.reencrypt_share(keys["Chris"])
    with pytest.raises(ValueError, match="could not compute same challenge"):
        pvss.add_reencrypted_share(chris_share[:-1] + bytes(((chris_share[-1] + 1) % 256,)))
            
    pvss.add_reencrypted_share(chris_share)

    with pytest.raises(ValueError, match="Duplicate index"):
        pvss.add_reencrypted_share(chris_share)


    secret1 = pvss.reconstruct_secret(recp_priv)
    assert secret0 == secret1

    while True:
        priv_emily, pub_emily = pvss.create_keypair("Emily")
        if priv_emily not in keys.values():
            break
        
        pass  # pragma: no cover

    with pytest.raises(ValueError, match="No matching public key found"):
        pvss.reencrypt_share(priv_emily)
