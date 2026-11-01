"""Pack-In's existing Tink wire formats using Home Assistant's cryptography.

Only the canonical P-256/SHA-256/DER and ECIES/AES-128-GCM templates are
accepted. This is a serialization adapter, not a new encryption protocol.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
import secrets
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_PREFIX = "type.googleapis.com/google.crypto.tink."
_MAX_KEYSET = 32768
_MAX_ENVELOPE = 1_500_000


class CryptoError(ValueError):
    """Malformed, unsupported, or unauthenticated input."""


def encode64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode64(value: str, limit: int = _MAX_ENVELOPE) -> bytes:
    if not isinstance(value, str) or len(value) > (limit * 4 // 3 + 8):
        raise CryptoError("Encoded value exceeds limit")
    try:
        data = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise CryptoError("Invalid base64") from exc
    if len(data) > limit:
        raise CryptoError("Decoded value exceeds limit")
    return data


def _varint(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise CryptoError("Unsupported integer")
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _int(number: int, value: int) -> bytes:
    return _varint(number << 3) + _varint(value)


def _bytes(number: int, value: bytes) -> bytes:
    return _varint(number << 3 | 2) + _varint(len(value)) + value


def _fields(data: bytes, allowed: set[int], repeated: set[int] | None = None) -> dict[int, Any]:
    if len(data) > _MAX_KEYSET:
        raise CryptoError("Keyset exceeds limit")
    position = 0
    result: dict[int, Any] = {}
    repeat = repeated or set()

    def read_int() -> int:
        nonlocal position
        value = 0
        for shift in range(0, 35, 7):
            if position >= len(data):
                break
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            if byte < 128:
                if value > 0xFFFFFFFF:
                    break
                return value
        raise CryptoError("Invalid protobuf integer")

    while position < len(data):
        tag = read_int()
        number, wire = tag >> 3, tag & 7
        if number not in allowed or wire not in (0, 2):
            raise CryptoError("Unsupported keyset field")
        if number in result and number not in repeat:
            raise CryptoError("Duplicate keyset field")
        if wire == 0:
            value: Any = read_int()
        else:
            length = read_int()
            if length > _MAX_KEYSET or position + length > len(data):
                raise CryptoError("Truncated keyset field")
            value = data[position : position + length]
            position += length
        if number in repeat:
            result.setdefault(number, []).append(value)
            if len(result[number]) > 8:
                raise CryptoError("Too many keys")
        else:
            result[number] = value
    return result


def _public_keys(encoded: str, kind: str) -> tuple[int, dict[int, tuple[ec.EllipticCurvePublicKey, bytes]]]:
    try:
        top = _fields(decode64(encoded, _MAX_KEYSET), {1, 2}, {2})
        primary = top[1]
        result: dict[int, tuple[ec.EllipticCurvePublicKey, bytes]] = {}
        for raw in top[2]:
            key = _fields(raw, {1, 2, 3, 4})
            key_id = key[3]
            if not isinstance(key_id, int) or key_id == 0 or key_id in result:
                raise CryptoError("Invalid key identity")
            if key[2] != 1 or key[4] != 1:
                raise CryptoError("Only enabled TINK keys are supported")
            key_data = _fields(key[1], {1, 2, 3})
            if key_data[1] != (_PREFIX + kind + "PublicKey").encode() or key_data[3] != 3:
                raise CryptoError("Unexpected key type")
            public = _fields(key_data[2], {1, 2, 3, 4})
            if public.get(1, 0) != 0:
                raise CryptoError("Unsupported key version")
            params = _fields(public[2], {1, 2, 3})
            if kind == "Ecdsa":
                if params != {1: 3, 2: 2, 3: 2}:
                    raise CryptoError("Unsupported signing parameters")
                salt = b""
            else:
                kem = _fields(params[1], {1, 2, 11})
                dem = _fields(params[2], {2})
                template = _fields(dem[2], {1, 2, 3})
                aes = _fields(template[2], {2, 3})
                if (
                    kem.get(1) != 2
                    or kem.get(2) != 3
                    or params[3] != 1
                    or template[1] != (_PREFIX + "AesGcmKey").encode()
                    or aes.get(2) != 16
                    or aes.get(3, 0) != 0
                ):
                    raise CryptoError("Unsupported encryption parameters")
                salt = kem.get(11, b"")
                if not isinstance(salt, bytes) or len(salt) > 1024:
                    raise CryptoError("Unsupported HKDF salt")
            coordinates = []
            for number in (3, 4):
                coordinate = public[number]
                if not isinstance(coordinate, bytes) or not 1 <= len(coordinate) <= 33:
                    raise CryptoError("Invalid coordinate")
                value = int.from_bytes(coordinate, "big")
                if value.bit_length() > 256:
                    raise CryptoError("Invalid coordinate size")
                coordinates.append(value)
            point = ec.EllipticCurvePublicNumbers(*coordinates, ec.SECP256R1()).public_key()
            result[key_id] = (point, salt)
        if primary not in result:
            raise CryptoError("Primary key is missing")
        return primary, result
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, CryptoError):
            raise
        raise CryptoError("Invalid public keyset") from exc


def _public_keyset(key: ec.EllipticCurvePrivateKey, key_id: int, kind: str) -> str:
    point = key.public_key().public_numbers()
    if kind == "Ecdsa":
        params = _int(1, 3) + _int(2, 2) + _int(3, 2)
    else:
        kem = _int(1, 2) + _int(2, 3)
        template = _bytes(1, (_PREFIX + "AesGcmKey").encode()) + _bytes(2, _int(2, 16)) + _int(3, 3)
        params = _bytes(1, kem) + _bytes(2, _bytes(2, template)) + _int(3, 1)
    public = _bytes(2, params) + _bytes(3, point.x.to_bytes(32, "big")) + _bytes(4, point.y.to_bytes(32, "big"))
    key_data = _bytes(1, (_PREFIX + kind + "PublicKey").encode()) + _bytes(2, public) + _int(3, 3)
    entry = _bytes(1, key_data) + _int(2, 1) + _int(3, key_id) + _int(4, 1)
    return encode64(_int(1, key_id) + _bytes(2, entry))


def verify(data: bytes, signature: bytes, public_keyset: str) -> None:
    if not 13 <= len(signature) <= 80 or signature[0] != 1:
        raise CryptoError("Invalid signature format")
    _, keys = _public_keys(public_keyset, "Ecdsa")
    key_id = int.from_bytes(signature[1:5], "big")
    if key_id not in keys:
        raise CryptoError("Unknown signing key")
    try:
        keys[key_id][0].verify(signature[5:], data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as exc:
        raise CryptoError("Invalid signature") from exc


def _context_part(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256 or "|" in value:
        raise CryptoError("Invalid encryption context")
    return value


def event_aad(pack: str, event: str, device: str, sequence: int, event_type: str, epoch: int) -> bytes:
    if type(sequence) is not int or not 1 <= sequence <= 2**53 - 1:
        raise CryptoError("Invalid device sequence")
    if type(epoch) is not int or not 1 <= epoch <= 2**31 - 1:
        raise CryptoError("Invalid key epoch")
    parts = [_context_part(v) for v in (pack, event, device, event_type)]
    return f"pack-in-event|1|{parts[0]}|{parts[1]}|{parts[2]}|{sequence}|{parts[3]}|{epoch}".encode()


def wrap_context(pack_id: str, epoch: int) -> bytes:
    if type(epoch) is not int or epoch < 1:
        raise CryptoError("Invalid key epoch")
    return f"pack-in-wrapped-key|v1|{_context_part(pack_id)}|{epoch}".encode()


@dataclass(repr=False)
class DeviceIdentity:
    """Private material stays in HA's local storage and backups."""

    encryption_key: ec.EllipticCurvePrivateKey = field(repr=False)
    signing_key: ec.EllipticCurvePrivateKey = field(repr=False)
    encryption_id: int
    signing_id: int

    @classmethod
    def generate(cls) -> DeviceIdentity:
        return cls(
            ec.generate_private_key(ec.SECP256R1()),
            ec.generate_private_key(ec.SECP256R1()),
            secrets.randbelow(2**31 - 1) + 1,
            secrets.randbelow(2**31 - 1) + 1,
        )

    def export(self) -> dict[str, Any]:
        def private(key: ec.EllipticCurvePrivateKey) -> str:
            return encode64(
                key.private_bytes(
                    serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                )
            )

        return {
            "encryption_key": private(self.encryption_key),
            "signing_key": private(self.signing_key),
            "encryption_id": self.encryption_id,
            "signing_id": self.signing_id,
        }

    @classmethod
    def restore(cls, value: dict[str, Any]) -> DeviceIdentity:
        def private(name: str) -> ec.EllipticCurvePrivateKey:
            key = serialization.load_der_private_key(decode64(value[name], 4096), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
                raise CryptoError("Unsupported private key")
            return key

        for name in ("encryption_id", "signing_id"):
            if type(value.get(name)) is not int or not 1 <= value[name] <= 2**31 - 1:
                raise CryptoError("Invalid key identity")
        return cls(private("encryption_key"), private("signing_key"), value["encryption_id"], value["signing_id"])

    @property
    def public(self) -> dict[str, str]:
        return {
            "encryptionPublicKey": _public_keyset(self.encryption_key, self.encryption_id, "EciesAeadHkdf"),
            "signingPublicKey": _public_keyset(self.signing_key, self.signing_id, "Ecdsa"),
            "keyAlgorithm": "P256-ECDSA",
        }

    def sign(self, data: bytes) -> bytes:
        return b"\x01" + self.signing_id.to_bytes(4, "big") + self.signing_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def wrap(self, clear: bytes, recipient: str, context: bytes) -> bytes:
        key_id, keys = _public_keys(recipient, "EciesAeadHkdf")
        public, salt = keys[key_id]
        ephemeral = ec.generate_private_key(ec.SECP256R1())
        point = ephemeral.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        shared = ephemeral.exchange(ec.ECDH(), public)
        key = HKDF(hashes.SHA256(), 16, salt or None, context).derive(point + shared)
        nonce = secrets.token_bytes(12)
        return b"\x01" + key_id.to_bytes(4, "big") + point + nonce + AESGCM(key).encrypt(nonce, clear, b"")

    def unwrap(self, encrypted: bytes, context: bytes) -> bytes:
        if len(encrypted) < 98 or encrypted[:5] != b"\x01" + self.encryption_id.to_bytes(4, "big"):
            raise CryptoError("Unknown wrapping key")
        point, nonce, ciphertext = encrypted[5:70], encrypted[70:82], encrypted[82:]
        try:
            public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
            shared = self.encryption_key.exchange(ec.ECDH(), public)
            key = HKDF(hashes.SHA256(), 16, None, context).derive(point + shared)
            return AESGCM(key).decrypt(nonce, ciphertext, b"")
        except ValueError as exc:
            raise CryptoError("Invalid wrapped key") from exc

    def encrypt_event(
        self,
        clear: bytes,
        pack_key: bytes,
        *,
        pack: str,
        event: str,
        device: str,
        sequence: int,
        event_type: str,
        epoch: int,
    ) -> str:
        if len(pack_key) != 32 or len(clear) > _MAX_ENVELOPE // 2:
            raise CryptoError("Invalid event size or key")
        aad = event_aad(pack, event, device, sequence, event_type, epoch)
        nonce = secrets.token_bytes(12)
        encrypted = AESGCM(pack_key).encrypt(nonce, clear, aad)
        return ".".join(
            ("1", str(epoch), encode64(nonce), encode64(encrypted), encode64(self.sign(aad + nonce + encrypted)))
        )


def decrypt_event(
    encoded: str,
    pack_key: bytes,
    sender: str,
    *,
    pack: str,
    event: str,
    device: str,
    sequence: int,
    event_type: str,
    epoch: int,
) -> bytes:
    if not isinstance(encoded, str) or len(encoded) > _MAX_ENVELOPE:
        raise CryptoError("Invalid event size")
    parts = encoded.split(".")
    if len(parts) != 5 or parts[0] != "1" or parts[1] != str(epoch) or len(pack_key) != 32:
        raise CryptoError("Unsupported envelope")
    nonce, ciphertext, signature = (decode64(v) for v in parts[2:])
    if len(nonce) != 12 or len(ciphertext) < 16:
        raise CryptoError("Invalid envelope")
    aad = event_aad(pack, event, device, sequence, event_type, epoch)
    verify(aad + nonce + ciphertext, signature, sender)
    return AESGCM(pack_key).decrypt(nonce, ciphertext, aad)


def seal_cache(value: dict[str, Any], local_key: bytes, pack_id: str) -> str:
    nonce = secrets.token_bytes(12)
    clear = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    return encode64(nonce + AESGCM(local_key).encrypt(nonce, clear, ("packin-ha-cache|1|" + pack_id).encode()))


def open_cache(value: str, local_key: bytes, pack_id: str) -> dict[str, Any]:
    raw = decode64(value, 32_000_000)
    if len(raw) < 28:
        raise CryptoError("Invalid cache")
    result = json.loads(AESGCM(local_key).decrypt(raw[:12], raw[12:], ("packin-ha-cache|1|" + pack_id).encode()))
    if not isinstance(result, dict):
        raise CryptoError("Invalid cache")
    return result
