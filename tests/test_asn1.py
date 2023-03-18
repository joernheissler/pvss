import pytest

from pvss import asn1


def test_not_der() -> None:
    with pytest.raises(ValueError, match="Does not encode back to original"):
        # Should be encoded as 02 01 55
        asn1.PrivateKey.load(b"\x30\x04\x02\x02\x00\x55")


def test_system_parameters() -> None:
    params = asn1.SystemParameters.load(
        bytes.fromhex("3012060c2b0601040183ae0001000100020204d2")
    )
    assert params.native == {"algorithm": "qr_mod_p", "parameters": 1234}

    params = asn1.SystemParameters.load(bytes.fromhex("3010060c2b0601040183ae00010001010500"))
    assert params.native == {"algorithm": "ristretto_255", "parameters": None}
