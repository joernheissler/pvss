from __future__ import annotations

from hashlib import sha256
from typing import Iterable, List, Union, Sequence

import asn1
from groups import Qr, QrValue, Zq, ZqValue
from lazy import lazy

Int = Union[int, QrValue, ZqValue]


def prod(items):
    it = iter(items)
    result = next(it)
    for tmp in it:
        result *= tmp
    return result


class SystemParameters:
    asn1: asn1.SystemParameters

    def __init__(self, asn1: asn1.SystemParameters) -> None:
        self.asn1 = asn1

        # XXX verify asn1

    @classmethod
    def decode(cls, data: ByteString) -> SystemParameters:
        return cls(asn1.SystemParameters.load(data))

    @classmethod
    def create(
        cls, group: Int, gen_g: Int, gen_h: Int, gen_G: Int, gen_H: Int
    ) -> SystemParameters:
        return cls(
            asn1.SystemParameters(
                {
                    "group": int(group),
                    "gen_g": int(gen_g),
                    "gen_h": int(gen_h),
                    "gen_G": int(gen_G),
                    "gen_H": int(gen_H),
                }
            )
        )

    @property
    def der(self) -> bytes:
        return self.asn1.dump()

    @lazy
    def img_group(self) -> Qr:
        return Qr.load(self.asn1["group"])

    @lazy
    def pre_group(self) -> Zq:
        return Zq.load(self.img_group.len)

    @lazy
    def g(self) -> QrValue:
        return self.img_group(self.asn1["gen_g"])

    @lazy
    def h(self) -> QrValue:
        return self.img_group(self.asn1["gen_h"])

    @lazy
    def G(self) -> QrValue:
        return self.img_group(self.asn1["gen_G"])

    @lazy
    def H(self) -> QrValue:
        return self.img_group(self.asn1["gen_H"])


class PrivateKey:
    asn1: asn1.PrivateKey
    params: SystemParameters

    def __init__(self, params: SystemParameters, asn1: asn1.PrivateKey) -> None:
        self.params = params
        self.asn1 = asn1
        # XXX verify asn1

    @classmethod
    def decode(cls, params: SystemParameters, data: ByteString) -> PrivateKey:
        return cls(params, asn1.PrivateKey.load(data))

    @classmethod
    def create(cls, params: SystemParameters, priv: Int) -> PrivateKey:
        return cls(params, asn1.PrivateKey({"priv": int(priv)}))

    @property
    def der(self) -> bytes:
        return self.asn1.dump()

    @lazy
    def priv(self) -> ZqValue:
        return self.params.pre_group(self.asn1["priv"])

    def pub(self, name: str) -> PublicKey:
        return PublicKey.create(
            self.params,
            name=name,
            pub0=self.params.G ** self.priv,
            pub1=self.params.H ** self.priv,
        )


class PublicKey:
    asn1: asn1.PublicKey
    params: SystemParameters

    def __init__(self, params: SystemParameters, asn1: asn1.PublicKey) -> None:
        self.params = params
        self.asn1 = asn1
        # XXX verify asn1

    @classmethod
    def decode(cls, params: SystemParameters, data: ByteString) -> PublicKey:
        return cls(params, asn1.PublicKey.load(data))

    @classmethod
    def create(
        cls, params: SystemParameters, name: str, pub0: Int, pub1: Int
    ) -> PublicKey:
        return cls(
            params,
            asn1.PublicKey({"name": str(name), "pub0": int(pub0), "pub1": int(pub1)}),
        )

    @property
    def der(self) -> bytes:
        return self.asn1.dump()

    @lazy
    def name(self) -> str:
        return str(self.asn1["name"])

    @lazy
    def pub0(self) -> QrValue:
        return self.params.img_group(self.asn1["pub0"])

    @lazy
    def pub1(self) -> QrValue:
        return self.params.img_group(self.asn1["pub1"])

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False

        return self.der == other.der


class Secret:
    asn1: asn1.Secret
    params: SystemParameters

    def __init__(self, params: SystemParameters, asn1: asn1.Secret) -> None:
        self.params = params
        self.asn1 = asn1
        # XXX verify asn1

    @classmethod
    def decode(cls, params: SystemParameters, data: ByteString) -> Secret:
        return cls(params, asn1.Secret.load(data))

    @classmethod
    def create(cls, params: SystemParameters, secret: Int) -> Secret:
        return cls(params, asn1.Secret({"secret": int(secret)}))

    @property
    def der(self) -> bytes:
        return self.asn1.dump()

    @lazy
    def secret(self) -> QrValue:
        return self.params.img_group(self.asn1["secret"])


class Share:
    asn1: asn1.Share
    params: SystemParameters

    def __init__(self, params: SystemParameters, asn1: asn1.Share) -> None:
        self.params = params
        self.asn1 = asn1
        # XXX verify asn1

    @classmethod
    def decode(cls, params: SystemParameters, data: ByteString) -> Share:
        return cls(params, asn1.Share.load(data))

    @classmethod
    def create(
        cls, params: SystemParameters, pub: PublicKey, share: Int, resp: Tuple[Int, Int]
    ) -> Share:
        return cls(
            params,
            asn1.Share(
                {
                    "pub": pub.asn1,
                    "share": int(share),
                    "response_x": int(resp[0]),
                    "response_y": int(resp[1]),
                }
            ),
        )

    @property
    def der(self) -> bytes:
        return self.asn1.dump()

    @lazy
    def pub(self) -> PublicKey:
        return PublicKey(self.params, self.asn1["pub"])

    @lazy
    def share(self) -> QrValue:
        return self.params.img_group(self.asn1["share"])

    @lazy
    def resp(self) -> QrValue:
        return (
            self.params.pre_group(self.asn1["response_x"]),
            self.params.pre_group(self.asn1["response_y"]),
        )


class SharedSecret:
    asn1: asn1.SharedSecret
    params: SystemParameters

    def __init__(self, params: SystemParameters, asn1: asn1.SharedSecret) -> None:
        self.params = params
        self.asn1 = asn1
        # XXX verify asn1

    @classmethod
    def decode(cls, params: SystemParameters, data: ByteString) -> SharedSecret:
        return cls(params, asn1.SharedSecret.load(data))

    @classmethod
    def create(
        cls,
        params: SystemParameters,
        shares: Iterable[Share],
        coeffs: Iterable[Int],
        challenge: ByteString,
    ) -> SharedSecret:
        return cls(
            params,
            asn1.SharedSecret(
                {
                    "shares": [share.asn1 for share in shares],
                    "coefficients": [int(coeff) for coeff in coeffs],
                    "challenge": bytes(challenge),
                }
            ),
        )

    @property
    def der(self) -> bytes:
        return self.asn1.dump()

    @lazy
    def shares(self) -> List[Share]:
        return [Share(self.params, share) for share in self.asn1["shares"]]

    @lazy
    def coefficients(self) -> List[QrValue]:
        return [self.params.img_group(coeff) for coeff in self.asn1["coefficients"]]

    @lazy
    def challenge(self) -> bytes:
        return bytes(self.asn1["challenge"])

    def verify(self) -> None:
        X = [
            prod(c ** (i ** j) for j, c in enumerate(self.coefficients))
            for i in range(1, len(self.shares) + 1)
        ]

        c = int.from_bytes(self.challenge, "big")
        r = [
            (
                (self.params.g ** share.resp[0])
                * (self.params.h ** share.resp[1])
                * (xi ** -c),
                (share.pub.pub0 ** share.resp[0])
                * (share.pub.pub1 ** share.resp[1])
                * (share.share ** -c),
            )
            for xi, share in zip(X, self.shares)
        ]

        challenge = compute_challenge(
            params=self.params,
            coeffs=self.coefficients,
            pubs=[share.pub for share in self.shares],
            commitments=X,
            shares=[share.share for share in self.shares],
            randoms=r,
        )

        if challenge != self.challenge:
            raise ValueError("Verification failed: could not compute same challenge")


class DecryptedShare:
    asn1: asn1.DecryptedShare
    params: SystemParameters
    shared_secret: SharedSecret

    def __init__(self, params: SystemParameters, shared_secret: SharedSecret, asn1: asn1.DecryptedShare) -> None:
        self.params = params
        self.shared_secret = shared_secret
        self.asn1 = asn1
        # XXX verify asn1

    @classmethod
    def decode(cls, params: SystemParameters, shared_secret: SharedSecret, data: ByteString) -> DecryptedShare:
        return cls(params, shared_secret, asn1.DecryptedShare.load(data))

    @classmethod
    def create(cls, params: SystemParameters, shared_secret: SharedSecret, idx: int, share: Int) -> DecryptedShare:
        return cls(params, shared_secret, asn1.DecryptedShare({"idx": idx, "share": int(share)}))

    @property
    def der(self) -> bytes:
        return self.asn1.dump()

    @lazy
    def idx(self) -> int:
        return int(self.asn1["idx"])

    @lazy
    def share(self) -> QrValue:
        return self.params.img_group(self.asn1["share"])

    # XXX verify


def compute_challenge(
    params: SystemParameters,
    coeffs: Sequence[Int],
    pubs: Sequence[PublicKey],
    commitments: Sequence[Int],
    shares: Sequence[Int],
    randoms: Sequence[Tuple[Int, Int]],
) -> bytes:
    lengths = set(map(len, [pubs, commitments, shares, randoms]))
    if len(lengths) != 1:
        raise ValueError("Not all parameters have the same length")

    hash_input = asn1.HashInput(
        {
            "parameters": params.asn1,
            "coefficients": [int(coeff) for coeff in coeffs],
            "users": [
                {
                    "pub": pub.asn1,
                    "commitment": int(commitment),
                    "random_commitment": int(rand_commit),
                    "share": int(share),
                    "random_share": int(rand_share),
                }
                for pub, commitment, share, (rand_commit, rand_share) in zip(
                    pubs, commitments, shares, randoms
                )
            ],
        }
    ).dump()

    return sha256(hash_input).digest()
