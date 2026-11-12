import pytest

from tgtrust import blind_rsa


def test_roundtrip_produces_standard_pss_signature(issuer_key):
    pub = issuer_key.public_key()
    msg = b"hello agent"
    blinded, state = blind_rsa.blind(pub, msg)
    sig = blind_rsa.finalize(pub, msg, blind_rsa.blind_sign(issuer_key, blinded), state)
    assert blind_rsa.verify(pub, msg, sig)


def test_signer_never_sees_final_values(issuer_key):
    pub = issuer_key.public_key()
    msg = b"token"
    blinded, state = blind_rsa.blind(pub, msg)
    blind_sig = blind_rsa.blind_sign(issuer_key, blinded)
    sig = blind_rsa.finalize(pub, msg, blind_sig, state)
    assert blinded != blind_rsa.emsa_pss_encode(msg, pub.key_size - 1)
    assert blind_sig != sig


def test_same_message_blinds_differently(issuer_key):
    pub = issuer_key.public_key()
    a, _ = blind_rsa.blind(pub, b"same")
    b, _ = blind_rsa.blind(pub, b"same")
    assert a != b


def test_signature_does_not_transfer_to_other_message(issuer_key):
    pub = issuer_key.public_key()
    blinded, state = blind_rsa.blind(pub, b"one")
    sig = blind_rsa.finalize(pub, b"one", blind_rsa.blind_sign(issuer_key, blinded), state)
    assert not blind_rsa.verify(pub, b"two", sig)


def test_finalize_rejects_wrong_message(issuer_key):
    pub = issuer_key.public_key()
    blinded, state = blind_rsa.blind(pub, b"one")
    with pytest.raises(blind_rsa.BlindSignatureError):
        blind_rsa.finalize(pub, b"two", blind_rsa.blind_sign(issuer_key, blinded), state)


@pytest.mark.parametrize("bad", [b"", b"\x00" * 256, b"\xff" * 256, b"\x01" * 10])
def test_blind_sign_rejects_malformed_input(issuer_key, bad):
    with pytest.raises(blind_rsa.BlindSignatureError):
        blind_rsa.blind_sign(issuer_key, bad)
