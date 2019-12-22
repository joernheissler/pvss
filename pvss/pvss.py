from __future__ import annotations

import hmac
from abc import ABC, abstractmethod
from fractions import Fraction
from functools import reduce
from hashlib import sha256
from itertools import zip_longest
from operator import mul
from typing import (
    TYPE_CHECKING,
    Any,
    ByteString,
    Dict,
    Generator,
    Iterable,
    Iterator,
    List,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    get_type_hints,
)

from asn1crypto.core import Asn1Value

from . import asn1
from .groups import ImageGroup, ImageValue, PreGroup, PreGroupValue

if TYPE_CHECKING:
    lazy = property
else:
    from lazy import lazy


def zip_strict(*args: Iterable[Any]) -> Iterator[Any]:
    """
    Like zip, but raise an exception unless all iterables have the same size
    """

    sentinel = object()
    for things in zip_longest(*args, fillvalue=sentinel):
        if any(thing is sentinel for thing in things):
            raise Exception("Not all iters finished at the same time")
        yield things


_T0 = TypeVar("_T0")


def prod(items: Iterable[_T0], initializer: _T0 = None) -> _T0:
    """
    Product function, like sum() but with multiplication.

    Params:
        items: items to multiply
        initializer: Optional initializer

    Returns:
        product
    """

    if initializer is None:
        return reduce(mul, items)
    else:
        return reduce(mul, items, initializer)


_T1 = TypeVar("_T1", bound="Asn1Object")


class Asn1Object(ABC):
    pvss: Pvss
    asn1: Asn1Value

    def __init__(self, pvss: Pvss, asn1: Asn1Value) -> None:
        self.pvss = pvss
        self.asn1 = asn1
        self._validate()

    @classmethod
    def from_der(cls: Type[_T1], pvss: Pvss, data: ByteString) -> _T1:
        return cls(pvss, get_type_hints(cls)["asn1"].load(data))

    @property
    def der(self) -> bytes:
        return self.asn1.dump()

    @property
    def params(self) -> SystemParameters:
        return self.pvss.params

    @abstractmethod
    def _validate(self) -> None:
        pass

    def __eq__(self, other: Any) -> bool:
        if type(self) is not type(other):
            return False

        return self.der == other.der


class SystemParameters(Asn1Object):
    ALGO: str
    asn1: asn1.SystemParameters

    _algos: Dict[str, Type[SystemParameters]] = {}

    def __new__(cls, pvss: Pvss, asn1: asn1.SystemParameters) -> SystemParameters:
        algo = asn1["algorithm"].native
        return super().__new__(cls._algos[algo])

    def __init_subclass__(cls) -> None:
        """
        Register sub classes
        """
        super().__init_subclass__()
        cls._algos[cls.ALGO] = cls

    @classmethod
    def create(cls, pvss: Pvss, params: Any) -> SystemParameters:
        return cls(pvss, asn1.SystemParameters({"algorithm": cls.ALGO, "parameters": params}))

    @property
    @abstractmethod
    def pre_group(self) -> PreGroup:
        """
        """

    @lazy
    def g(self) -> ImageValue:
        return self._make_gen("g")

    @lazy
    def h(self) -> ImageValue:
        return self._make_gen("h")

    @lazy
    def G(self) -> ImageValue:
        return self._make_gen("G")

    @lazy
    def H(self) -> ImageValue:
        return self._make_gen("H")

    def _validate(self) -> None:
        if self.asn1["algorithm"].native != self.ALGO:
            raise TypeError

        # Load groups to validate them
        self.img_group
        self.pre_group

    @property
    @abstractmethod
    def img_group(self) -> ImageGroup:
        pass

    @abstractmethod
    def _make_gen(self, seed: str) -> ImageValue:
        pass


class PrivateKey(Asn1Object):
    asn1: asn1.PrivateKey

    def _validate(self) -> None:
        """
        """
        self.priv

    @classmethod
    def create(cls, pvss: Pvss, priv: PreGroupValue) -> PrivateKey:
        return cls(pvss, asn1.PrivateKey({"priv": priv.asn1}))

    @classmethod
    def create_random(cls, pvss: Pvss) -> PrivateKey:
        return cls.create(pvss, pvss.params.pre_group.rand_nonzero)

    @lazy
    def priv(self) -> PreGroupValue:
        return self.pvss.params.pre_group(self.asn1["priv"])

    def pub(self, name: str) -> PublicKey:
        return PublicKey.create(
            self.pvss, name, self.params.G ** self.priv, self.params.H ** self.priv
        )


class PublicKey(Asn1Object):
    asn1: asn1.PublicKey

    def _validate(self) -> None:
        """
        """
        self.pub0
        self.pub1
        if not self.name:
            raise ValueError()

    @classmethod
    def create(cls, pvss: Pvss, name: str, pub0: ImageValue, pub1: ImageValue) -> PublicKey:
        return cls(
            pvss, asn1.PublicKey({"name": str(name), "pub0": pub0.asn1, "pub1": pub1.asn1})
        )

    @lazy
    def name(self) -> str:
        return str(self.asn1["name"])

    @lazy
    def pub0(self) -> ImageValue:
        return self.params.img_group(self.asn1["pub0"])

    @lazy
    def pub1(self) -> ImageValue:
        return self.params.img_group(self.asn1["pub1"])


class Secret(Asn1Object):
    asn1: asn1.Secret

    @classmethod
    def create(cls, pvss: Pvss, secret: ImageValue) -> Secret:
        return cls(pvss, asn1.Secret({"secret": secret.asn1}))

    @lazy
    def secret(self) -> ImageValue:
        return self.params.img_group(self.asn1["secret"])

    def _validate(self) -> None:
        """
        """
        self.secret

    @classmethod
    def reconstruct(cls, pvss: Pvss, private_key: PrivateKey) -> Secret:
        """
        Decrypt the re-encrypted shares with the private key and reconstruct the secret

        Args:
            pvss: Pvss object with public values
            der_private_key: Recipient's Private key

        Returns:
            Secret
        """

        if len(pvss.reencrypted_shares) < len(pvss.shares.coefficients):
            raise Exception(
                f"Need at least {len(pvss.shares.coefficients)} shares, only got {len(pvss.reencrypted_shares)}"
            )

        shares = {
            reenc_share.idx: reenc_share.c2 * ((reenc_share.c1 ** private_key.priv) ** -1)
            for reenc_share in pvss.reencrypted_shares
        }

        secret = prod(
            share0
            ** prod(
                (Fraction(idx1, idx1 - idx0) for idx1 in shares.keys() if idx0 != idx1),
                Fraction(1),
            )
            for idx0, share0 in shares.items()
        )

        return cls.create(pvss, secret)


class Share(Asn1Object):
    asn1: asn1.Share

    @classmethod
    def create(
        cls,
        pvss: Pvss,
        pub_name: str,
        share: ImageValue,
        resp: Tuple[PreGroupValue, PreGroupValue],
    ) -> Share:
        return cls(
            pvss,
            asn1.Share(
                {
                    "pub": pub_name,
                    "share": share.asn1,
                    "response_x": resp[0].asn1,
                    "response_y": resp[1].asn1,
                }
            ),
        )

    @lazy
    def pub_name(self) -> str:
        return self.asn1["pub"].native

    @lazy
    def pub(self) -> PublicKey:
        """
        """

        for pub in self.pvss.shareholder_public_keys:
            if pub.name == self.pub_name:
                return pub
        raise KeyError

    @lazy
    def share(self) -> ImageValue:
        return self.params.img_group(self.asn1["share"])

    @lazy
    def resp(self) -> Tuple[PreGroupValue, PreGroupValue]:
        return (
            self.params.pre_group(self.asn1["response_x"]),
            self.params.pre_group(self.asn1["response_y"]),
        )

    def _validate(self) -> None:
        """
        """
        # XXX check if pubname in pvss
        self.share
        self.resp


class SharedSecret(Asn1Object):
    asn1: asn1.SharedSecret

    @classmethod
    def create(
        cls,
        pvss: Pvss,
        shares: Iterable[Share],
        coeffs: Iterable[ImageValue],
        challenge: ByteString,
    ) -> SharedSecret:
        return cls(
            pvss,
            asn1.SharedSecret(
                {
                    "shares": [share.asn1 for share in shares],
                    "coefficients": [coeff.asn1 for coeff in coeffs],
                    "challenge": bytes(challenge),
                }
            ),
        )

    @lazy
    def shares(self) -> List[Share]:
        return [Share(self.pvss, share) for share in self.asn1["shares"]]

    @lazy
    def coefficients(self) -> List[ImageValue]:
        return [self.params.img_group(coeff) for coeff in self.asn1["coefficients"]]

    @lazy
    def digest(self) -> bytes:
        return bytes(self.asn1["challenge"])

    @lazy
    def challenge(self) -> int:
        return int.from_bytes(self.digest, "big")

    def _validate(self) -> None:
        X = [
            prod(c ** (i ** j) for j, c in enumerate(self.coefficients))
            for i in range(1, len(self.shares) + 1)
        ]

        min_c = -self.challenge
        r = [
            (
                (self.params.g ** share.resp[0])
                * (self.params.h ** share.resp[1])
                * (xi ** min_c),
                (share.pub.pub0 ** share.resp[0])
                * (share.pub.pub1 ** share.resp[1])
                * (share.share ** min_c),
            )
            for xi, share in zip(X, self.shares)
        ]

        challenge = SharesChallenge.create(
            pvss=self.pvss,
            pubs=[share.pub for share in self.shares],
            coeffs=self.coefficients,
            commitments=X,
            shares=[share.share for share in self.shares],
            randoms=r,
        )

        if challenge.digest != self.digest:
            raise ValueError("Verification failed: could not compute same challenge")

    @classmethod
    def create_shared_secret(
        cls, pvss: Pvss, qualified_size: int
    ) -> Tuple[Secret, SharedSecret]:
        """
        Create a secret, split it and compute the encrypted shares.

        Args:
            pvss: Pvss object with public values
            qualified_size: Number of shares required to reconstruct the secret

        Returns:
            Random secret and the encrypted shares
        """

        # Shareholder public keys
        pub = pvss.shareholder_public_keys

        # polynomials, chosen from Z_q
        alpha = Poly(pvss.params.pre_group.rand for __ in range(qualified_size))
        beta = Poly(pvss.params.pre_group.rand for __ in range(qualified_size))

        # Secret to be shared
        S = Secret.create(pvss, (pvss.params.G ** alpha(0)) * (pvss.params.H ** beta(0)))

        # commitments for coeffs
        C = [(pvss.params.g ** a) * (pvss.params.h ** b) for a, b in zip(alpha, beta)]

        # Encrypted shares
        Y = [(pi.pub0 ** alpha(i)) * (pi.pub1 ** beta(i)) for i, pi in enumerate(pub, 1)]

        # X_i computed by prover
        X = [
            (pvss.params.g ** alpha(i)) * (pvss.params.h ** beta(i))
            for i in range(1, len(pub) + 1)
        ]

        # rand [0,q)
        k = [(pvss.params.pre_group.rand, pvss.params.pre_group.rand) for __ in range(len(pub))]

        # random commitments
        r = [
            (
                (pvss.params.g ** ki[0]) * (pvss.params.h ** ki[1]),
                (pi.pub0 ** ki[0]) * (pi.pub1 ** ki[1]),
            )
            for pi, ki in zip(pub, k)
        ]

        # challenge is computed by hash function
        challenge = SharesChallenge.create(pvss, pub, C, X, Y, r)
        c = challenge.challenge

        # response
        s = [(ki[0] + alpha(i) * c, ki[1] + beta(i) * c) for i, ki in enumerate(k, 1)]

        shared_secret = SharedSecret.create(
            pvss=pvss,
            shares=[
                Share.create(pvss=pvss, pub_name=pub_key.name, share=share, resp=resp)
                for pub_key, share, resp in zip(pub, Y, s)
            ],
            coeffs=C,
            challenge=challenge.digest,
        )

        return S, shared_secret


class ReencryptedShare(Asn1Object):
    asn1: asn1.ReencryptedShare

    @classmethod
    def create(
        cls,
        pvss: Pvss,
        idx: int,
        c1: ImageValue,
        c2: ImageValue,
        response_priv: PreGroupValue,
        response_a: PreGroupValue,
        response_b: PreGroupValue,
        response_v: PreGroupValue,
        response_w: PreGroupValue,
        challenge: ByteString,
    ) -> ReencryptedShare:
        return cls(
            pvss,
            asn1.ReencryptedShare(
                {
                    "idx": idx,
                    "c1": c1.asn1,
                    "c2": c2.asn1,
                    "response_priv": response_priv.asn1,
                    "response_a": response_a.asn1,
                    "response_b": response_b.asn1,
                    "response_v": response_v.asn1,
                    "response_w": response_w.asn1,
                    "challenge": bytes(challenge),
                }
            ),
        )

    @lazy
    def idx(self) -> int:
        return int(self.asn1["idx"])

    @lazy
    def c1(self) -> ImageValue:
        return self.params.img_group(self.asn1["c1"])

    @lazy
    def c2(self) -> ImageValue:
        return self.params.img_group(self.asn1["c2"])

    @lazy
    def response_priv(self) -> PreGroupValue:
        return self.params.pre_group(self.asn1["response_priv"])

    @lazy
    def response_a(self) -> PreGroupValue:
        return self.params.pre_group(self.asn1["response_a"])

    @lazy
    def response_b(self) -> PreGroupValue:
        return self.params.pre_group(self.asn1["response_b"])

    @lazy
    def response_v(self) -> PreGroupValue:
        return self.params.pre_group(self.asn1["response_v"])

    @lazy
    def response_w(self) -> PreGroupValue:
        return self.params.pre_group(self.asn1["response_w"])

    @lazy
    def digest(self) -> bytes:
        return bytes(self.asn1["challenge"])

    @lazy
    def challenge(self) -> int:
        return int.from_bytes(self.digest, "big")

    def _validate(self) -> None:
        """`
        """

        minus_c = -self.challenge
        pub = self.pvss.shareholder_public_keys[self.idx - 1]

        ry = (
            (self.c2 ** self.response_priv)
            * (self.pvss.recipient_public_key.pub0 ** self.response_v)
            * (self.pvss.recipient_public_key.pub1 ** self.response_w)
        ) * (self.pvss.shares.shares[self.idx - 1].share ** minus_c)

        ru = ((self.params.G * self.params.H) ** self.response_priv) * (
            (pub.pub0 * pub.pub1) ** minus_c
        )
        rc1 = ((self.params.G ** self.response_a) * (self.params.H ** self.response_b)) * (
            self.c1 ** minus_c
        )
        rone = (
            (self.c1 ** self.response_priv)
            * (self.params.G ** self.response_v)
            * (self.params.H ** self.response_w)
        )

        challenge = ReencryptedChallenge.create(self.pvss, ry, ru, rc1, rone)

        if challenge.digest != self.digest:
            raise ValueError("Verification failed: could not compute same challenge")

    @classmethod
    def reencrypt(cls, pvss: Pvss, private_key: PrivateKey) -> ReencryptedShare:
        """
        Decrypt a share of the encrypted secret with the private_key and
        re-encrypt it with another public key

        Args:
            pvss: Pvss object with public values
            private_key: A shareholder's private key

        Returns:
            Re-encrypted share
        """

        # Locate our share
        for idx, enc_share in enumerate(pvss.shares.shares, 1):
            if enc_share.pub == private_key.pub(enc_share.pub_name):
                break
        else:
            raise ValueError("No matching public key found")

        # decrypt our share
        share = enc_share.share ** private_key.priv.inv

        # Reencrypt share with Elgamal encryption using the recipient's public key
        a = pvss.params.pre_group.rand
        b = pvss.params.pre_group.rand
        c1 = (pvss.params.G ** a) * (pvss.params.H ** b)
        c2 = (
            share
            * (pvss.recipient_public_key.pub0 ** a)
            * (pvss.recipient_public_key.pub1 ** b)
        )

        v = -a * private_key.priv
        w = -b * private_key.priv
        ka, kb, kv, kw, kpi = (pvss.params.pre_group.rand for __ in range(5))

        ry = (
            (c2 ** kpi)
            * (pvss.recipient_public_key.pub0 ** kv)
            * (pvss.recipient_public_key.pub1 ** kw)
        )
        ru = (pvss.params.G * pvss.params.H) ** kpi
        rc1 = (pvss.params.G ** ka) * (pvss.params.H ** kb)
        rone = (c1 ** kpi) * (pvss.params.G ** kv) * (pvss.params.H ** kw)

        challenge = ReencryptedChallenge.create(pvss, ry, ru, rc1, rone)

        c = challenge.challenge
        spi = kpi + private_key.priv * c
        sa = ka + a * c
        sb = kb + b * c
        sv = kv + v * c
        sw = kw + w * c

        return ReencryptedShare.create(pvss, idx, c1, c2, spi, sa, sb, sv, sw, challenge.digest)


class Challenge(Asn1Object):
    def _validate(self) -> None:
        """
        Noop because this is never loaded
        """
        # XXX is still loaded in constructor. What to do?!

    @lazy
    def digest(self) -> bytes:
        """
        Compute the sha256 digest over the DER encoding
        """
        return sha256(self.der).digest()

    @lazy
    def challenge(self) -> int:
        """
        Convert the digest into an integer so it can be used in the algorithms
        """
        return int.from_bytes(self.digest, "big")


class SharesChallenge(Challenge):
    asn1: asn1.SharesChallenge

    @classmethod
    def create(
        cls,
        pvss: Pvss,
        pubs: Iterable[PublicKey],
        coeffs: Iterable[ImageValue],
        commitments: Iterable[ImageValue],
        shares: Iterable[ImageValue],
        randoms: Iterable[Tuple[ImageValue, ImageValue]],
    ) -> SharesChallenge:
        """
        """
        return cls(
            pvss,
            asn1.SharesChallenge(
                {
                    "parameters": pvss.params.asn1,
                    "coefficients": [coeff.asn1 for coeff in coeffs],
                    "users": [
                        {
                            "pub": pub.asn1,
                            "commitment": commitment.asn1,
                            "random_commitment": rand_commit.asn1,
                            "share": share.asn1,
                            "random_share": rand_share.asn1,
                        }
                        for pub, commitment, share, (rand_commit, rand_share) in zip_strict(
                            pubs, commitments, shares, randoms
                        )
                    ],
                }
            ),
        )


class ReencryptedChallenge(Challenge):
    asn1: asn1.ReencryptedChallenge

    @classmethod
    def create(
        cls,
        pvss: Pvss,
        rand_c2pub: ImageValue,
        rand_pub: ImageValue,
        rand_c1: ImageValue,
        rand_one: ImageValue,
    ) -> ReencryptedChallenge:
        """
        """
        return cls(
            pvss,
            asn1.ReencryptedChallenge(
                {
                    "parameters": pvss.params.asn1,
                    "public_keys": [pub.asn1 for pub in pvss.ordered_shareholder_public_keys],
                    "shares": pvss.shares.asn1,
                    "recipient_public_key": pvss.recipient_public_key.asn1,
                    "rand_c2pub": rand_c2pub.asn1,
                    "rand_pub": rand_pub.asn1,
                    "rand_c1": rand_c1.asn1,
                    "rand_one": rand_one.asn1,
                }
            ),
        )


class Pvss:
    _params: SystemParameters
    _shareholder_public_keys: List[PublicKey]
    _shares: SharedSecret
    _reencrypted_shares: List[ReencryptedShare]
    _recipient_public_key: PublicKey

    def __init__(self) -> None:
        self._shareholder_public_keys = []
        self._reencrypted_shares = []

    @property
    def params(self) -> SystemParameters:
        return self._params

    @params.setter
    def params(self, data: ByteString) -> None:
        self._params = SystemParameters.from_der(self, data)

    @property
    def shareholder_public_keys(self) -> List[PublicKey]:
        return list(self._shareholder_public_keys)

    @property
    def ordered_shareholder_public_keys(self) -> List[PublicKey]:
        """
        Ordered list of public keys according to SharedSecret structure

        Returns:
            Ordered list of public keys
        """
        pubs = {pub.name: pub for pub in self.shareholder_public_keys}
        return [pubs[share.pub_name] for share in self.shares.shares]

    def add_shareholder_public_key(self, data: ByteString) -> None:
        """
        Add a shareholder public key to the internal state.

        Args:
            data: DER encoded public key

        Raises:
            ValueError: On duplicate name or public key value
        """
        pub_key = PublicKey.from_der(self, data)
        for pub in self._shareholder_public_keys:
            if pub_key.name == pub.name:
                raise ValueError(f"Duplicate name: {pub_key.name}")
            if pub_key.pub0 == pub.pub0 or pub_key.pub1 == pub.pub1:
                raise ValueError(
                    f"Duplicate public key value in keys {pub_key.name} and {pub.name}"
                )
        self._shareholder_public_keys.append(pub_key)

    @property
    def shares(self) -> SharedSecret:
        return self._shares

    @shares.setter
    def shares(self, data: ByteString) -> None:
        self._shares = SharedSecret.from_der(self, data)

    @property
    def reencrypted_shares(self) -> List[ReencryptedShare]:
        return self._reencrypted_shares

    def add_reencrypted_share(self, data: ByteString) -> None:
        """
        Add a re-encrypted share to the internal state.

        Args:
            data: DER encoded re-encrypted share

        Raises:
            ValueError: On duplicate
        """
        reenc_share = ReencryptedShare.from_der(self, data)
        if reenc_share.idx in {s.idx for s in self._reencrypted_shares}:
            raise ValueError(f"Duplicate index: {reenc_share.idx}")
        self._reencrypted_shares.append(reenc_share)

    @property
    def recipient_public_key(self) -> PublicKey:
        return self._recipient_public_key

    @recipient_public_key.setter
    def recipient_public_key(self, data: ByteString) -> None:
        self._recipient_public_key = PublicKey.from_der(self, data)

    def create_keypair(self, name: str) -> Tuple[bytes, bytes]:
        """
        Create a random key pair.

        Args:
            name: Name of key; will be included in the public key.

        Returns:
            DER encoded private key and public key
        """
        priv = PrivateKey.create_random(self)
        return priv.der, priv.pub(name).der

    def share_secret(self, qualified_size: int) -> Tuple[bytes, bytes]:
        """
        Create a secret, split it and compute the encrypted shares.

        Args:
            qualified_size: Number of shares required to reconstruct the secret

        Returns:
            DER encoded shared secret and the DER encoded encrypted shares
        """

        secret, shares = SharedSecret.create_shared_secret(self, qualified_size)
        return secret.der, shares.der

    def reencrypt_share(self, der_private_key: ByteString) -> bytes:
        """
        Decrypt a share of the encrypted secret with the private_key and
        re-encrypt it with another public key

        Args:
            der_private_key: A shareholder's DER encoded private key

        Returns:
            DER encoded re-encrypted share
        """

        private_key = PrivateKey.from_der(self, der_private_key)
        return ReencryptedShare.reencrypt(self, private_key).der

    def reconstruct_secret(self, der_private_key: ByteString) -> bytes:
        """
        Decrypt the re-encrypted shares with the private key and reconstruct the secret

        Args:
            der_private_key: Recipient's DER encoded private key

        Returns:
            DER encoded secret
        """

        private_key = PrivateKey.from_der(self, der_private_key)
        return Secret.reconstruct(self, private_key).der


class Poly:
    _coeffs: List[PreGroupValue]

    def __init__(self, coeffs: Iterable[PreGroupValue]) -> None:
        self._coeffs = list(coeffs)

    def __call__(self, x: int) -> PreGroupValue:
        return sum(coeff * (x ** j) for j, coeff in enumerate(self._coeffs))

    def __len__(self) -> int:
        return len(self._coeffs)

    def __getitem__(self, idx: int) -> PreGroupValue:
        return self._coeffs[idx]

    def __repr__(self) -> str:
        return "Poly([" + ", ".join(str(coeff) for coeff in self._coeffs) + "])"
