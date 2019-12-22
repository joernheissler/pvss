from __future__ import annotations

from hashlib import md5
from typing import ByteString, Type, TypeVar, Union, cast

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
    def load(cls: Type[_T], encoded_data: ByteString, strict: bool = False, **kwargs) -> _T:
        self = cast(_T, super().load(encoded_data, strict=True, **kwargs))

        if type(self) is not cls:
            raise TypeError(type(self))

        if self.dump(True) != encoded_data:
            raise ValueError("Does not encode back to original")

        return self


class PreGroupValue(Integer):
    """
    """


class ImgGroupValue(Choice):
    _alternatives = [("QrValue", Integer), ("ECPoint", OctetString)]


class PvssAlgorithmId(ObjectIdentifier):
    # XXX Should get a better OID
    _base_oid = f'2.25.{int.from_bytes(md5(b"pvss").digest(), "little")}.1'
    _map = {
        _base_oid + ".0": "qr_mod_p",
        _base_oid + ".1": "ristretto_255",
        _base_oid + ".2": "ristretto_448",
        _base_oid + ".3": "nist_p_256",
    }


class SystemParameters(VerifiedLoader, Sequence):
    _fields = [("algorithm", PvssAlgorithmId), ("parameters", Any)]

    _oid_pair = ("algorithm", "parameters")
    _oid_specs = {
        "qr_mod_p": Integer,
        "ristretto_255": Null,
        "ristretto_448": Null,
        "nist_p_256": Null,
    }


class PublicKey(VerifiedLoader, Sequence):
    _fields = [("name", UTF8String), ("pub0", ImgGroupValue), ("pub1", ImgGroupValue)]


class PrivateKey(VerifiedLoader, Sequence):
    _fields = [("priv", PreGroupValue)]


class Secret(VerifiedLoader, Sequence):
    _fields = [("secret", ImgGroupValue)]


class Share(Sequence):
    _fields = [
        ("pub", UTF8String),
        ("share", ImgGroupValue),
        ("response_x", PreGroupValue),
        ("response_y", PreGroupValue),
    ]


class Shares(SequenceOf):
    _child_spec = Share


class Coefficients(SequenceOf):
    _child_spec = ImgGroupValue


class SharedSecret(VerifiedLoader, Sequence):
    _fields = [("shares", Shares), ("coefficients", Coefficients), ("challenge", OctetString)]


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
        ("recipient_public_key", PublicKey),
        ("rand_c2pub", ImgGroupValue),
        ("rand_pub", ImgGroupValue),
        ("rand_c1", ImgGroupValue),
        ("rand_one", ImgGroupValue),
    ]


class ReencryptedShare(Sequence):
    _fields = [
        ("idx", Integer),
        ("c1", ImgGroupValue),
        ("c2", ImgGroupValue),
        ("response_priv", PreGroupValue),
        ("response_a", PreGroupValue),
        ("response_b", PreGroupValue),
        ("response_v", PreGroupValue),
        ("response_w", PreGroupValue),
        ("challenge", OctetString),
    ]
