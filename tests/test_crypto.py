"""Synthetic compatibility and adversarial vectors; no real account keys."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

import pytest
from cryptography.exceptions import InvalidTag

_path = Path(__file__).parents[1] / "custom_components/packin/crypto.py"
_spec = importlib.util.spec_from_file_location("packin_crypto_test", _path)
crypto = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = crypto
_spec.loader.exec_module(crypto)


@pytest.fixture
def vector():
    return json.loads((Path(__file__).parent / "fixtures/tink_android.json").read_text(encoding="utf8"))


def test_android_library_event_decrypts(vector):
    assert crypto.decrypt_event(
        vector["envelope"], crypto.decode64(vector["pack_key"]), vector["signing_public"], **vector["context"]
    ) == crypto.decode64(vector["clear"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("pack", "another-pack"),
        ("event", "another-event"),
        ("device", "another-device"),
        ("sequence", 12),
        ("event_type", "grocery.item.upserted"),
        ("epoch", 8),
    ],
)
def test_event_context_cannot_be_substituted(vector, field, value):
    context = dict(vector["context"], **{field: value})
    with pytest.raises((crypto.CryptoError, InvalidTag)):
        crypto.decrypt_event(
            vector["envelope"], crypto.decode64(vector["pack_key"]), vector["signing_public"], **context
        )


@pytest.mark.parametrize("part", [2, 3, 4])
def test_tamper_rejected(vector, part):
    parts = vector["envelope"].split(".")
    damaged = bytearray(crypto.decode64(parts[part]))
    damaged[-1] ^= 1
    parts[part] = crypto.encode64(damaged)
    with pytest.raises((crypto.CryptoError, InvalidTag)):
        crypto.decrypt_event(
            ".".join(parts), crypto.decode64(vector["pack_key"]), vector["signing_public"], **vector["context"]
        )


def test_unknown_sender_rejected(vector):
    other = crypto.DeviceIdentity.generate()
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_event(
            vector["envelope"],
            crypto.decode64(vector["pack_key"]),
            other.public["signingPublicKey"],
            **vector["context"],
        )


def test_identity_round_trip_and_signatures():
    identity = crypto.DeviceIdentity.generate()
    restored = crypto.DeviceIdentity.restore(identity.export())
    assert restored.public == identity.public
    signature = restored.sign(b"approved payload")
    crypto.verify(b"approved payload", signature, identity.public["signingPublicKey"])
    with pytest.raises(crypto.CryptoError):
        crypto.verify(b"changed payload", signature, identity.public["signingPublicKey"])


def test_wrapping_context_and_recipient_bound():
    sender, receiver = crypto.DeviceIdentity.generate(), crypto.DeviceIdentity.generate()
    context = crypto.wrap_context("test-pack", 7)
    key = bytes(range(32))
    wrapped = sender.wrap(key, receiver.public["encryptionPublicKey"], context)
    assert receiver.unwrap(wrapped, context) == key
    with pytest.raises((crypto.CryptoError, InvalidTag)):
        receiver.unwrap(wrapped, crypto.wrap_context("other-pack", 7))
    with pytest.raises(crypto.CryptoError):
        sender.unwrap(wrapped, context)


def test_wrong_pack_key_rejected(vector):
    with pytest.raises(InvalidTag):
        crypto.decrypt_event(vector["envelope"], b"x" * 32, vector["signing_public"], **vector["context"])


def test_cache_authenticated_and_pack_bound():
    key = bytes(range(32))
    sealed = crypto.seal_cache({"last_sequence": 3, "items": []}, key, "test-pack")
    assert crypto.open_cache(sealed, key, "test-pack")["last_sequence"] == 3
    with pytest.raises(InvalidTag):
        crypto.open_cache(sealed, key, "other-pack")


def test_public_key_parser_rejects_private_key_material():
    identity = crypto.DeviceIdentity.generate()
    raw = crypto.decode64(identity.public["signingPublicKey"])
    # Duplicate scalar field must not override the primary key.
    with pytest.raises(crypto.CryptoError):
        crypto._public_keys(crypto.encode64(raw + b"\x08\x01"), "Ecdsa")
    with pytest.raises(crypto.CryptoError):
        crypto._public_keys(identity.public["encryptionPublicKey"], "Ecdsa")


@pytest.mark.parametrize("value", ["%", "a" * 3, "", "1.2.3", "2.7.YQ.Yg.Yw"])
def test_malformed_envelopes_fail_closed(vector, value):
    with pytest.raises((crypto.CryptoError, InvalidTag)):
        crypto.decrypt_event(value, crypto.decode64(vector["pack_key"]), vector["signing_public"], **vector["context"])
