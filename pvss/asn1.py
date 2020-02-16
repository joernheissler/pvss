from __future__ import annotations

from typing import Any as _Any
from typing import ByteString, Dict, Type, TypeVar, cast

from asn1crypto.core import (
    Any,
    Asn1Value,
    Choice,
    Integer,
    Null,
    ObjectIdentifier,
    OctetString,
    Sequence,
    SequenceOf,
    UTF8String,
)

_T = TypeVar("_T", bound="VerifiedLoader")


class VerifiedLoader(Asn1Value):
    @classmethod
    def load(
        cls: Type[_T], encoded_data: ByteString, strict: bool = False, **kwargs: Dict[str, _Any]
    ) -> _T:
        self = super().load(encoded_data, strict=True, **kwargs)

        if self.dump(True) != encoded_data:
            raise ValueError("Does not encode back to original")

        return self


# fmt: off
class PreGroupValue(Integer):
    """
    """


class ImgGroupValue(Choice):
    _alternatives = [
        ("QrValue", Integer),
        ("ECPoint", OctetString),
    ]


class PvssAlgorithmId(ObjectIdentifier):
    _base_oid = "1.3.6.1.4.1.55040.1.0.1"
    _map = {
        _base_oid + ".0": "qr_mod_p",
        _base_oid + ".1": "ristretto_255",
        # _base_oid + ".2": "ristretto_448", (or decaf?)
        # _base_oid + ".3": "nist_p_256", (or decaf?)
    }


class SystemParameters(VerifiedLoader, Sequence):
    _fields = [
        ("algorithm", PvssAlgorithmId),
        ("parameters", Any),
    ]

    _oid_pair = ("algorithm", "parameters")
    _oid_specs = {
        "qr_mod_p": Integer,
        "ristretto_255": Null,
        # "ristretto_448": Null,
        # "nist_p_256": Null,
    }


class PublicKey(VerifiedLoader, Sequence):
    _fields = [
        ("name", UTF8String),
        ("pub0", ImgGroupValue),
        ("pub1", ImgGroupValue),
    ]


class PrivateKey(VerifiedLoader, Sequence):
    _fields = [
        ("priv", PreGroupValue),
    ]


class Secret(VerifiedLoader, Sequence):
    _fields = [
        ("secret", ImgGroupValue),
    ]


class Share(Sequence):
    _fields = [
        ("pub", UTF8String),
        ("share", ImgGroupValue),
        ("response_f0", PreGroupValue),
        ("response_f1", PreGroupValue),
    ]


class Shares(SequenceOf):
    _child_spec = Share


class Coefficients(SequenceOf):
    _child_spec = ImgGroupValue


class SharedSecret(VerifiedLoader, Sequence):
    _fields = [
        ("shares", Shares),
        ("coefficients", Coefficients),
        ("challenge", OctetString),
    ]


class HashInputUser(Sequence):
    _fields = [
        ("pub", PublicKey),
        ("commitment", ImgGroupValue),
        ("random_commitment", ImgGroupValue),
        ("share", ImgGroupValue),
        ("random_share", ImgGroupValue),
    ]


class HashInputUsers(SequenceOf):
    _child_spec = HashInputUser


class SharesChallenge(Sequence):
    _fields = [
        ("parameters", SystemParameters),
        ("coefficients", Coefficients),
        ("users", HashInputUsers),
    ]


class PublicKeys(SequenceOf):
    _child_spec = PublicKey


class ReencryptedChallenge(Sequence):
    _fields = [
        ("parameters", SystemParameters),
        ("public_keys", PublicKeys),
        ("shares", SharedSecret),
        ("receiver_public_key", PublicKey),
        ("rand_pub", ImgGroupValue),
        ("rand_share", ImgGroupValue),
        ("rand_elg_a", ImgGroupValue),
        ("rand_id", ImgGroupValue),
    ]


class ReencryptedShare(VerifiedLoader, Sequence):
    _fields = [
        ("idx", Integer),
        ("elg_a", ImgGroupValue),
        ("elg_b", ImgGroupValue),
        ("response_priv", PreGroupValue),
        ("response_v0", PreGroupValue),
        ("response_v1", PreGroupValue),
        ("response_w0", PreGroupValue),
        ("response_w1", PreGroupValue),
        ("challenge", OctetString),
    ]


class PvssContainer(Choice):
    _alternatives = [
        ("parameters", SystemParameters, {"explicit": 0}),
        ("priv_key", PrivateKey, {"explicit": 1}),
        ("user_pub", PublicKey, {"explicit": 2}),
        ("recv_pub", PublicKey, {"explicit": 3}),
        ("shared_secret", SharedSecret, {"explicit": 4}),
        ("reencrypted_share", ReencryptedShare, {"explicit": 5}),
    ]
# fmt: on
