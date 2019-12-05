from __future__ import annotations

from typing import ByteString, Union

from asn1crypto.core import Integer, OctetString, Sequence, SequenceOf, UTF8String
from groups import Qr, QrValue, Zq


class VerifiedLoader:
    @classmethod
    def load(cls, encoded_data: ByteString, strict=False, **kwargs):
        self = super().load(encoded_data, strict=True, **kwargs)

        if type(self) is not cls:
            raise TypeError(type(self))

        if self.dump(True) != encoded_data:
            raise ValueError("Does not encode back to original")

        return self


class SystemParameters(VerifiedLoader, Sequence):
    _fields = [
        ("group", Integer),
        ("gen_g", Integer),
        ("gen_h", Integer),
        ("gen_G", Integer),
        ("gen_H", Integer),
    ]


class PublicKey(VerifiedLoader, Sequence):
    _fields = [("name", UTF8String), ("pub0", Integer), ("pub1", Integer)]


class PrivateKey(VerifiedLoader, Sequence):
    _fields = [("priv", Integer)]


class Secret(VerifiedLoader, Sequence):
    _fields = [("secret", Integer)]


class Share(Sequence):
    _fields = [
        ("pub", PublicKey),
        ("share", Integer),
        ("response_x", Integer),
        ("response_y", Integer),
    ]


class Shares(SequenceOf):
    _child_spec = Share


class Coefficients(SequenceOf):
    _child_spec = Integer


class SharedSecret(VerifiedLoader, Sequence):
    _fields = [
        ("shares", Shares),
        ("coefficients", Coefficients),
        ("challenge", OctetString),
    ]


class HashInputUser(Sequence):
    _fields = [
        ("pub", PublicKey),
        ("commitment", Integer),
        ("random_commitment", Integer),
        ("share", Integer),
        ("random_share", Integer),
    ]


class HashInputUsers(SequenceOf):
    _child_spec = HashInputUser


class HashInput(Sequence):
    _fields = [
        ("parameters", SystemParameters),
        ("coefficients", Coefficients),
        ("users", HashInputUsers),
    ]

class DecryptedShare(Sequence):
    _fields = [
        ("idx", Integer),
        ("share", Integer),
        # XXX proof
    ]
