from __future__ import annotations

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
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
    get_type_hints,
    overload,
)

from asn1crypto.core import Asn1Value, Integer, OctetString, SequenceOf

from . import asn1 as _asn1
from .groups import ImageGroup, ImageValue, PreGroup, PreGroupValue

if TYPE_CHECKING:  # pragma: no cover
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
            raise ValueError("Not all iters finished at the same time")
        yield things


_T0 = TypeVar("_T0")


def prod(items: Iterable[_T0], initializer: Optional[_T0] = None) -> _T0:
    """
    Product function, like sum() but with multiplication.

    Args:
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
        """
        """

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, type(self)):
            return False

        return self.der == other.der


_T2 = TypeVar("_T2", bound="SystemParameters")


class SystemParameters(Asn1Object):
    ALGO: str
    asn1: _asn1.SystemParameters

    def __new__(cls, pvss: Pvss, asn1: _asn1.SystemParameters) -> SystemParameters:
        algo = asn1["algorithm"].native
        impl: Type[SystemParameters]
        if algo == "qr_mod_p":
            from . import qr

            impl = qr.QrParameters
        elif algo == "ristretto_255":
            from . import ristretto_255

            impl = ristretto_255.Ristretto255Parameters
        else:
            raise ValueError(f"Algorithm {algo} not implemented")
        return cast(SystemParameters, super().__new__(impl))

    @classmethod
    def create(cls: Type[_T2], pvss: Pvss, params: Any) -> _T2:
        return cls(pvss, _asn1.SystemParameters({"algorithm": cls.ALGO, "parameters": params}))

    @property
    @abstractmethod
    def pre_group(self) -> PreGroup:
        """
        """

    @lazy
    def g(self) -> Tuple[ImageValue, ImageValue]:
        return self._make_gen("g_0"), self._make_gen("g_1")

    @lazy
    def G(self) -> Tuple[ImageValue, ImageValue]:
        return self._make_gen("G_0"), self._make_gen("G_1")

    def _validate(self) -> None:
        # Load groups to validate them
        self.img_group
        self.pre_group

    @property
    @abstractmethod
    def img_group(self) -> ImageGroup:
        """
        """

    @abstractmethod
    def _make_gen(self, seed: str) -> ImageValue:
        """
        """


class PrivateKey(Asn1Object):
    asn1: _asn1.PrivateKey

    def _validate(self) -> None:
        """
        """
        self.priv

    @classmethod
    def create(cls, pvss: Pvss, priv: PreGroupValue) -> PrivateKey:
        return cls(pvss, _asn1.PrivateKey({"priv": priv.asn1}))

    @classmethod
    def create_random(cls, pvss: Pvss) -> PrivateKey:
        return cls.create(pvss, pvss.params.pre_group.rand_nonzero)

    @lazy
    def priv(self) -> PreGroupValue:
        return self.pvss.params.pre_group(self.asn1["priv"])

    def pub(self, name: str) -> PublicKey:
        return PublicKey.create(
            self.pvss, name, (self.params.G[0] ** self.priv, self.params.G[1] ** self.priv)
        )


class PublicKey(Asn1Object):
    asn1: _asn1.PublicKey

    def _validate(self) -> None:
        """
        """
        self.pub
        if not self.name:
            raise ValueError()

    @classmethod
    def create(cls, pvss: Pvss, name: str, pub: Tuple[ImageValue, ImageValue]) -> PublicKey:
        return cls(
            pvss, _asn1.PublicKey({"name": str(name), "pub0": pub[0].asn1, "pub1": pub[1].asn1})
        )

    @lazy
    def name(self) -> str:
        return str(self.asn1["name"])

    @lazy
    def pub(self) -> Tuple[ImageValue, ImageValue]:
        return (
            self.params.img_group(self.asn1["pub0"]),
            self.params.img_group(self.asn1["pub1"]),
        )


class Secret(Asn1Object):
    asn1: _asn1.Secret

    @classmethod
    def create(cls, pvss: Pvss, secret: ImageValue) -> Secret:
        return cls(pvss, _asn1.Secret({"secret": secret.asn1}))

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
            der_private_key: Receiver's Private key

        Returns:
            Secret
        """

        if len(pvss.reencrypted_shares) < len(pvss.shares.coefficients):
            raise Exception(
                f"Need at least {len(pvss.shares.coefficients)} shares, only got {len(pvss.reencrypted_shares)}"
            )

        shares = {
            reenc_share.idx: reenc_share.elg_b * ((reenc_share.elg_a ** private_key.priv) ** -1)
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
    asn1: _asn1.Share

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
            _asn1.Share(
                {
                    "pub": pub_name,
                    "share": share.asn1,
                    "response_f0": resp[0].asn1,
                    "response_f1": resp[1].asn1,
                }
            ),
        )

    @lazy
    def pub_name(self) -> str:
        return cast(str, self.asn1["pub"].native)

    @lazy
    def pub(self) -> PublicKey:
        """
        """

        return self.pvss.user_public_keys[self.pub_name]

    @lazy
    def share(self) -> ImageValue:
        return self.params.img_group(self.asn1["share"])

    @lazy
    def resp(self) -> Tuple[PreGroupValue, PreGroupValue]:
        return (
            self.params.pre_group(self.asn1["response_f0"]),
            self.params.pre_group(self.asn1["response_f1"]),
        )

    def _validate(self) -> None:
        """
        """
        # XXX check if pubname in pvss
        self.share
        self.resp


class SharedSecret(Asn1Object):
    asn1: _asn1.SharedSecret

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
            _asn1.SharedSecret(
                {
                    "shares": [share.asn1 for share in shares],
                    "coefficients": [coeff.asn1 for coeff in coeffs],
                    "challenge": bytes(challenge),
                }
            ),
        )

    @lazy
    def shares(self) -> List[Share]:
        return [Share(self.pvss, share) for share in cast(SequenceOf, self.asn1["shares"])]

    @lazy
    def coefficients(self) -> List[ImageValue]:
        return [
            self.params.img_group(coeff)
            for coeff in cast(SequenceOf, self.asn1["coefficients"])
        ]

    @lazy
    def digest(self) -> bytes:
        return bytes(cast(OctetString, self.asn1["challenge"]))

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
                (self.params.g[0] ** share.resp[0])
                * (self.params.g[1] ** share.resp[1])
                * (xi ** min_c),
                (share.pub.pub[0] ** share.resp[0])
                * (share.pub.pub[1] ** share.resp[1])
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

        # user public keys
        pub = pvss.user_public_keys.values()

        # polynomials, chosen from Z_q
        alpha = (
            Poly(
                (pvss.params.pre_group.rand for __ in range(qualified_size)),
                pvss.params.pre_group(0),
            ),
            Poly(
                (pvss.params.pre_group.rand for __ in range(qualified_size)),
                pvss.params.pre_group(0),
            ),
        )

        # secret to be split
        S = Secret.create(
            pvss, (pvss.params.G[0] ** alpha[0](0)) * (pvss.params.G[1] ** alpha[1](0))
        )

        # commitments for coeffs
        C = [
            (pvss.params.g[0] ** coeff[0]) * (pvss.params.g[1] ** coeff[1])
            for coeff in zip(alpha[0], alpha[1])
        ]

        # encrypted shares
        Y = [
            (pi.pub[0] ** alpha[0](i)) * (pi.pub[1] ** alpha[1](i))
            for i, pi in enumerate(pub, 1)
        ]

        # X_i computed by prover
        X = [
            (pvss.params.g[0] ** alpha[0](i)) * (pvss.params.g[1] ** alpha[1](i))
            for i in range(1, len(pub) + 1)
        ]

        # rand [0,q)
        k = [(pvss.params.pre_group.rand, pvss.params.pre_group.rand) for __ in range(len(pub))]

        # random commitments
        r = [
            (
                (pvss.params.g[0] ** ki[0]) * (pvss.params.g[1] ** ki[1]),
                (pi.pub[0] ** ki[0]) * (pi.pub[1] ** ki[1]),
            )
            for pi, ki in zip(pub, k)
        ]

        # challenge is computed by hash function
        challenge = SharesChallenge.create(pvss, pub, C, X, Y, r)
        c = challenge.challenge

        # response
        s = [(ki[0] + alpha[0](i) * c, ki[1] + alpha[1](i) * c) for i, ki in enumerate(k, 1)]

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
    asn1: _asn1.ReencryptedShare

    @classmethod
    def create(
        cls,
        pvss: Pvss,
        idx: int,
        elg_a: ImageValue,
        elg_b: ImageValue,
        response_priv: PreGroupValue,
        response_v: Tuple[PreGroupValue, PreGroupValue],
        response_w: Tuple[PreGroupValue, PreGroupValue],
        challenge: ByteString,
    ) -> ReencryptedShare:
        return cls(
            pvss,
            _asn1.ReencryptedShare(
                {
                    "idx": idx,
                    "elg_a": elg_a.asn1,
                    "elg_b": elg_b.asn1,
                    "response_priv": response_priv.asn1,
                    "response_v0": response_v[0].asn1,
                    "response_v1": response_v[1].asn1,
                    "response_w0": response_w[0].asn1,
                    "response_w1": response_w[1].asn1,
                    "challenge": bytes(challenge),
                }
            ),
        )

    @lazy
    def idx(self) -> int:
        return int(cast(Integer, self.asn1["idx"]))

    @lazy
    def elg_a(self) -> ImageValue:
        return self.params.img_group(self.asn1["elg_a"])

    @lazy
    def elg_b(self) -> ImageValue:
        return self.params.img_group(self.asn1["elg_b"])

    @lazy
    def response_priv(self) -> PreGroupValue:
        return self.params.pre_group(self.asn1["response_priv"])

    @lazy
    def response_v(self) -> Tuple[PreGroupValue, PreGroupValue]:
        return (
            self.params.pre_group(self.asn1["response_v0"]),
            self.params.pre_group(self.asn1["response_v1"]),
        )

    @lazy
    def response_w(self) -> Tuple[PreGroupValue, PreGroupValue]:
        return (
            self.params.pre_group(self.asn1["response_w0"]),
            self.params.pre_group(self.asn1["response_w1"]),
        )

    @lazy
    def digest(self) -> bytes:
        return bytes(cast(OctetString, self.asn1["challenge"]))

    @lazy
    def challenge(self) -> int:
        return int.from_bytes(self.digest, "big")

    @property
    def share(self) -> Share:
        return self.pvss.shares.shares[self.idx - 1]

    def _validate(self) -> None:
        """`
        """

        minus_c = -self.challenge
        pub = self.share.pub

        rand_share = (
            (self.elg_b ** self.response_priv)
            * (self.pvss.receiver_public_key.pub[0] ** self.response_v[0])
            * (self.pvss.receiver_public_key.pub[1] ** self.response_v[1])
        ) * (self.pvss.shares.shares[self.idx - 1].share ** minus_c)

        rand_pub = ((self.params.G[0] * self.params.G[1]) ** self.response_priv) * (
            (pub.pub[0] * pub.pub[1]) ** minus_c
        )
        rand_elg_a = (
            (self.params.G[0] ** self.response_w[0]) * (self.params.G[1] ** self.response_w[1])
        ) * (self.elg_a ** minus_c)
        rand_id = (
            (self.elg_a ** self.response_priv)
            * (self.params.G[0] ** self.response_v[0])
            * (self.params.G[1] ** self.response_v[1])
        )

        challenge = ReencryptedChallenge.create(
            self.pvss, rand_pub, rand_share, rand_elg_a, rand_id
        )

        if challenge.digest != self.digest:
            raise ValueError("Verification failed: could not compute same challenge")

    @classmethod
    def reencrypt(cls, pvss: Pvss, private_key: PrivateKey) -> ReencryptedShare:
        """
        Decrypt a share of the encrypted secret with the private_key and
        re-encrypt it with another public key

        Args:
            pvss: Pvss object with public values
            private_key: A user's private key

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

        # Reencrypt share with Elgamal encryption using the receiver's public key
        w = [pvss.params.pre_group.rand, pvss.params.pre_group.rand]
        elg_a = (pvss.params.G[0] ** w[0]) * (pvss.params.G[1] ** w[1])
        elg_b = (
            share
            * (pvss.receiver_public_key.pub[0] ** w[0])
            * (pvss.receiver_public_key.pub[1] ** w[1])
        )

        v = [-w[0] * private_key.priv, -w[1] * private_key.priv]
        kv = (pvss.params.pre_group.rand, pvss.params.pre_group.rand)
        kw = (pvss.params.pre_group.rand, pvss.params.pre_group.rand)
        kpi = pvss.params.pre_group.rand

        rand_share = (
            (elg_b ** kpi)
            * (pvss.receiver_public_key.pub[0] ** kv[0])
            * (pvss.receiver_public_key.pub[1] ** kv[1])
        )
        rand_pub = (pvss.params.G[0] * pvss.params.G[1]) ** kpi
        rand_elg_a = (pvss.params.G[0] ** kw[0]) * (pvss.params.G[1] ** kw[1])
        rand_id = (elg_a ** kpi) * (pvss.params.G[0] ** kv[0]) * (pvss.params.G[1] ** kv[1])

        challenge = ReencryptedChallenge.create(pvss, rand_pub, rand_share, rand_elg_a, rand_id)

        c = challenge.challenge
        resp_priv = kpi + private_key.priv * c
        resp_v = (kv[0] + v[0] * c, kv[1] + v[1] * c)
        resp_w = (kw[0] + w[0] * c, kw[1] + w[1] * c)

        return ReencryptedShare.create(
            pvss, idx, elg_a, elg_b, resp_priv, resp_v, resp_w, challenge.digest
        )


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
    asn1: _asn1.SharesChallenge

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
            _asn1.SharesChallenge(
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
    asn1: _asn1.ReencryptedChallenge

    @classmethod
    def create(
        cls,
        pvss: Pvss,
        rand_pub: ImageValue,
        rand_share: ImageValue,
        rand_elg_a: ImageValue,
        rand_id: ImageValue,
    ) -> ReencryptedChallenge:
        """
        """
        return cls(
            pvss,
            _asn1.ReencryptedChallenge(
                {
                    "parameters": pvss.params.asn1,
                    "public_keys": [share.pub.asn1 for share in pvss.shares.shares],
                    "shares": pvss.shares.asn1,
                    "receiver_public_key": pvss.receiver_public_key.asn1,
                    "rand_pub": rand_pub.asn1,
                    "rand_share": rand_share.asn1,
                    "rand_elg_a": rand_elg_a.asn1,
                    "rand_id": rand_id.asn1,
                }
            ),
        )


class Pvss:
    """
    Main class to work with Pvss. Stores all public messages and exposes the PVSS operations.
    """

    _params: SystemParameters
    _user_public_keys: Dict[str, PublicKey]
    _shares: SharedSecret
    _reencrypted_shares: List[ReencryptedShare]
    _receiver_public_key: PublicKey

    def __init__(self) -> None:
        """
        The constructor takes no parameters.
        """

        self._user_public_keys = {}
        self._reencrypted_shares = []

    @property
    def params(self) -> SystemParameters:
        """
        Retrieve system parameters.

        Returns:
            The system parameters.
        """

        return self._params

    def set_params(self, data: ByteString) -> SystemParameters:
        """
        Set system parameters.

        Args
            data: DER encoded system parameters.

        Returns:
            Decoded system parameters.

        Raises:
            Exception: If already set.
        """

        params = SystemParameters.from_der(self, data)
        if hasattr(self, "_params"):
            raise Exception("Parameters already set")
        self._params = params
        return params

    @property
    def user_public_keys(self) -> Dict[str, PublicKey]:
        """
        Retrieve all user public keys, as mapping from username to PublicKey.

        Returns:
            Mapping of username to PublicKey.
        """

        return dict(self._user_public_keys)

    def add_user_public_key(self, data: ByteString) -> PublicKey:
        """
        Add a user public key to the internal state.

        Args:
            data: DER encoded public key

        Returns:
            Decoded user public key.

        Raises:
            ValueError: On duplicate name or public key value
        """
        pub_key = PublicKey.from_der(self, data)

        for pub in self._user_public_keys.values():
            if pub_key.name == pub.name:
                raise ValueError(f"Duplicate name: {pub_key.name}")
            if pub_key.pub == pub.pub:
                raise ValueError(
                    f"Duplicate public key value in keys {pub_key.name} and {pub.name}"
                )
        self._user_public_keys[pub_key.name] = pub_key
        return pub_key

    @property
    def shares(self) -> SharedSecret:
        """
        Retrieve the shares of the secret.

        Returns:
            Shares of the secret.
        """

        return self._shares

    def set_shares(self, data: ByteString) -> SharedSecret:
        """
        Set the shares of the secret.

        Args:
            data: DER encoded secret shares.

        Returns:
            Decoded secret shares.

        Raises:
            Exception: If already set.
        """

        shares = SharedSecret.from_der(self, data)
        if hasattr(self, "_shares"):
            raise Exception("Shares already set")
        self._shares = shares
        return shares

    @property
    def reencrypted_shares(self) -> List[ReencryptedShare]:
        """
        Retrieve the list of reencrypted shares.

        Returns:
            List of reencrypted shares.
        """

        return self._reencrypted_shares

    def add_reencrypted_share(self, data: ByteString) -> ReencryptedShare:
        """
        Add a re-encrypted share to the internal state.

        Args:
            data: DER encoded re-encrypted share.

        Returns:
            Decoded reencrypted share.

        Raises:
            ValueError: On duplicate
        """
        reenc_share = ReencryptedShare.from_der(self, data)
        if reenc_share.idx in {s.idx for s in self._reencrypted_shares}:
            raise ValueError(f"Duplicate index: {reenc_share.idx}")
        self._reencrypted_shares.append(reenc_share)
        return reenc_share

    @property
    def receiver_public_key(self) -> PublicKey:
        """
        Retrieve receiver's public key.

        Returns:
            Receiver's public key.
        """

        return self._receiver_public_key

    def set_receiver_public_key(self, data: ByteString) -> PublicKey:
        """
        Add the receiver's public key to the internal state.

        Args:
            data: DER encoded receiver's public key.

        Returns:
            Decoded receiver's public key.

        Raises:
            Exception: On duplicate
        """

        pub = PublicKey.from_der(self, data)
        if hasattr(self, "_receiver_public_key"):
            raise Exception("Receiver key already set")
        self._receiver_public_key = pub
        return pub

    def create_user_keypair(self, name: str) -> Tuple[bytes, bytes]:
        """
        Create a random key pair for a user.

        Args:
            name: Name of key; will be included in the public key.

        Returns:
            DER encoded private key and public key
        """
        priv = PrivateKey.create_random(self)
        pub = priv.pub(name).der
        self.add_user_public_key(pub)
        return priv.der, pub

    def create_receiver_keypair(self, name: str) -> Tuple[bytes, bytes]:
        """
        Create a random key pair for the receiver.

        Args:
            name: Name of key; will be included in the public key.

        Returns:
            DER encoded private key and public key
        """
        priv = PrivateKey.create_random(self)
        pub = priv.pub(name).der
        self.set_receiver_public_key(pub)
        return priv.der, pub

    def share_secret(self, qualified_size: int) -> Tuple[bytes, bytes]:
        """
        Create a secret, split it and compute the encrypted shares.

        Args:
            qualified_size: Number of shares required to reconstruct the secret

        Returns:
            DER encoded shared secret and the DER encoded encrypted shares
        """

        secret, shares = SharedSecret.create_shared_secret(self, qualified_size)
        self.set_shares(shares.der)
        return secret.der, shares.der

    def reencrypt_share(self, der_private_key: ByteString) -> bytes:
        """
        Decrypt a share of the encrypted secret with the private_key and
        re-encrypt it with another public key

        Args:
            der_private_key: A user's DER encoded private key

        Returns:
            DER encoded re-encrypted share
        """

        private_key = PrivateKey.from_der(self, der_private_key)
        share = ReencryptedShare.reencrypt(self, private_key).der
        self.add_reencrypted_share(share)
        return share

    def reconstruct_secret(self, der_private_key: ByteString) -> bytes:
        """
        Decrypt the re-encrypted shares with the private key and reconstruct the secret

        Args:
            der_private_key: Receiver's DER encoded private key

        Returns:
            DER encoded secret
        """

        private_key = PrivateKey.from_der(self, der_private_key)
        return Secret.reconstruct(self, private_key).der


class Poly(Sequence[PreGroupValue]):
    """
    Polynomial
    """

    _coeffs: List[PreGroupValue]
    _zero: PreGroupValue

    def __init__(self, coeffs: Iterable[PreGroupValue], zero: PreGroupValue) -> None:
        self._coeffs = list(coeffs)
        self._zero = zero

    def __call__(self, i: int) -> PreGroupValue:
        return sum((coeff * (i ** j) for j, coeff in enumerate(self._coeffs)), self._zero)

    def __len__(self) -> int:
        return len(self._coeffs)

    @overload
    def __getitem__(self, index: int) -> PreGroupValue:
        """
        """

    @overload
    def __getitem__(self, index: slice) -> Sequence[PreGroupValue]:
        """
        """

    def __getitem__(
        self, idx: Union[int, slice]
    ) -> Union[PreGroupValue, Sequence[PreGroupValue]]:
        return self._coeffs[idx]

    def __repr__(self) -> str:
        return "Poly([" + ", ".join(str(coeff) for coeff in self._coeffs) + "])"
