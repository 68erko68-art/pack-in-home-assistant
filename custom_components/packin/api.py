"""Outbound-only, device-bound Pack-In API. Entity properties never call this."""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass, field
import hashlib
import json
import re
import secrets
import time
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit
from uuid import uuid4

import aiohttp

from .crypto import DeviceIdentity, CryptoError, decode64, encode64, verify, wrap_context
from .protocol import PROTOCOL_VERSION, SYNC_GENERATION

API_ORIGIN = "https://pack-in-beta-api.68erko68.workers.dev"
PREFIX = "/api/ha/v1"
MAX_RESPONSE = 1_000_000
WS_HEARTBEAT = 120
SCOPES = [
    "tasks:read",
    "tasks:write",
    "groceries:read",
    "groceries:write",
    "calendar:read",
    "members:read",
    "locations:read",
]


class PackInApiError(Exception):
    """Only a bounded category is safe to log; never carry response bodies."""

    def __init__(self, code: str, status: int = 0, retry_after: int = 0):
        self.code = code if isinstance(code, str) and re.fullmatch(r"[a-z0-9_]{1,80}", code) else "request_failed"
        self.status = status
        self.retry_after = max(0, min(86400, retry_after))
        super().__init__(self.code)

    @property
    def auth_failed(self) -> bool:
        return self.status in (401, 403)


async def deny_redirect(request: aiohttp.ClientRequest, handler: aiohttp.ClientHandlerType) -> aiohttp.ClientResponse:
    """Reject a redirect before aiohttp can forward a signed WebSocket request."""
    response = await handler(request)
    if 300 <= response.status < 400:
        response.close()
        raise PackInApiError("unexpected_redirect", response.status)
    return response


@dataclass(repr=False)
class Pairing:
    identity: DeviceIdentity = field(repr=False)
    request: dict[str, Any] = field(repr=False)
    expires_at: int = 0
    claim: dict[str, Any] | None = field(default=None, repr=False)
    requested_epoch: int | None = None

    @property
    def user_code(self) -> str:
        value = self.request["userCode"]
        return value[:4] + "-" + value[4:]


def new_pairing(display_name: str, scopes: list[str]) -> Pairing:
    selected = sorted(set(scopes) | {"members:read"})
    if not set(selected) <= set(SCOPES):
        raise ValueError("Unsupported permission")
    identity = DeviceIdentity.generate()
    return Pairing(
        identity,
        {
            "pairingId": "pair_" + uuid4().hex,
            "deviceId": "ha_" + uuid4().hex,
            "userCode": "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8)),
            "deviceCode": encode64(secrets.token_bytes(32)),
            "displayName": display_name.strip()[:80] or "Home Assistant",
            **{key: value for key, value in identity.public.items() if key != "keyAlgorithm"},
            "scopes": selected,
        },
    )


def install_keys(
    identity: DeviceIdentity, pack_id: str, wrapped: list[dict[str, Any]], existing: dict[str, str] | None = None
) -> dict[str, str]:
    result = dict(existing or {})
    if len(wrapped) > 256:
        raise CryptoError("Too many Pack key epochs")
    for item in wrapped:
        epoch = item.get("epoch")
        if type(epoch) is not int or epoch < 1:
            raise CryptoError("Invalid key epoch")
        context = wrap_context(pack_id, epoch)
        encrypted = decode64(item["encryptedKey"], 4096)
        verify(context + encrypted, decode64(item["signature"], 80), item["senderSigningPublicKey"])
        clear = identity.unwrap(encrypted, context)
        if len(clear) != 32:
            raise CryptoError("Invalid Pack key size")
        encoded = encode64(clear)
        if str(epoch) in result and result[str(epoch)] != encoded:
            raise CryptoError("The Pack key changed within an immutable epoch")
        result[str(epoch)] = encoded
    return result


class PackInApi:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        identity: DeviceIdentity,
        data: dict[str, Any] | None = None,
        checkpoint: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        *,
        _test_origin: str | None = None,
    ) -> None:
        self.session = session
        self.identity = identity
        self.data = dict(data or {})
        self.checkpoint = checkpoint
        self.metrics: Counter[str] = Counter()
        self._renew_lock = asyncio.Lock()
        self.origin = API_ORIGIN
        if _test_origin is not None:
            parsed = urlsplit(_test_origin)
            if (
                parsed.scheme != "http"
                or parsed.hostname not in {"127.0.0.1", "::1"}
                or parsed.username
                or parsed.password
            ):
                raise ValueError("Only a literal loopback address is allowed for tests")
            self.origin = _test_origin.rstrip("/")

    async def _save(self) -> None:
        if self.checkpoint is not None:
            await self.checkpoint(dict(self.data))

    def _headers(self, method: str, path: str, raw: bytes, credential: str, scheme: str) -> dict[str, str]:
        if not path.startswith(PREFIX + "/") or "|" in path or "://" in path:
            raise ValueError("Invalid Pack-In request path")
        timestamp = str(int(time.time() * 1000))
        nonce = encode64(secrets.token_bytes(18))
        message = "|".join(
            (
                "pack-in-ha-request",
                "1",
                method,
                path,
                timestamp,
                nonce,
                hashlib.sha256(raw).hexdigest(),
                hashlib.sha256(credential.encode()).hexdigest(),
            )
        )
        return {
            "accept": "application/json",
            "content-type": "application/json",
            "x-packin-ha-time": timestamp,
            "x-packin-ha-nonce": nonce,
            "x-packin-ha-signature": encode64(self.identity.sign(message.encode())),
            **({"authorization": scheme + " " + credential} if credential else {}),
        }

    @staticmethod
    def _retry_after(value: str | None) -> int:
        if value is None:
            return 0
        if value.isdigit():
            return 86400 if len(value) > 6 else min(86400, int(value))
        try:
            from email.utils import parsedate_to_datetime

            return max(0, min(86400, int(parsedate_to_datetime(value).timestamp() - time.time())))
        except (TypeError, ValueError):
            return 0

    async def _raw(
        self,
        method: str,
        path: str,
        value: dict[str, Any] | None = None,
        credential: str = "",
        scheme: str = "PackInHA",
    ) -> dict[str, Any]:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() if value is not None else b""
        headers = self._headers(method, path, raw, credential, scheme)
        self.metrics["http_requests"] += 1
        try:
            async with self.session.request(
                method,
                self.origin + path,
                data=raw if value is not None else None,
                headers=headers,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=20, connect=10),
            ) as response:
                chunks = bytearray()
                async for chunk in response.content.iter_chunked(16384):
                    chunks.extend(chunk)
                    if len(chunks) > MAX_RESPONSE:
                        raise PackInApiError("response_too_large", response.status)
                try:
                    result = json.loads(chunks)
                except (ValueError, UnicodeError):
                    result = None
                if not 200 <= response.status < 300:
                    error = result.get("error") if isinstance(result, dict) else None
                    code = error.get("code", "request_failed") if isinstance(error, dict) else "request_failed"
                    if 300 <= response.status < 400:
                        code = "unexpected_redirect"
                    raise PackInApiError(code, response.status, self._retry_after(response.headers.get("retry-after")))
                if not isinstance(result, dict):
                    raise PackInApiError("invalid_response")
                return result
        except (asyncio.TimeoutError, aiohttp.ClientError):
            raise PackInApiError("network_unavailable") from None

    @property
    def connection_path(self) -> str:
        identifier = self.data.get("connection_id", "")
        if not isinstance(identifier, str) or not re.fullmatch(r"ha_[a-f0-9]{32}", identifier):
            raise PackInApiError("invalid_connection", 401)
        return PREFIX + "/connections/" + identifier

    async def _merge_metadata(self, result: dict[str, Any]) -> None:
        mapping = {
            "packId": "pack_id",
            "userId": "user_id",
            "packName": "pack_name",
            "role": "role",
            "scopes": "scopes",
            "dataEpoch": "data_epoch",
            "keyEpoch": "key_epoch",
            "timeZoneId": "time_zone",
            "accessExpiresAt": "access_expires_at_ms",
            "refreshExpiresAt": "refresh_expires_at_ms",
            "members": "members",
            "authorityMode": "authority_mode",
        }
        for remote, local in mapping.items():
            if remote in result:
                self.data[local] = result[remote]
        if "wrappedKeys" in result:
            self.data["pack_keys"] = await asyncio.to_thread(
                install_keys, self.identity, self.data["pack_id"], result["wrappedKeys"], self.data.get("pack_keys", {})
            )
        await self._save()

    async def ensure_session(self, *, force: bool = False) -> None:
        if self.data.get("reauth_reason"):
            raise PackInApiError("connection_requires_reauth", 401)
        async with self._renew_lock:
            if (
                not force
                and not self.data.get("pending_rotation")
                and (self.data.get("access_expires_at_ms", 0) > int(time.time() * 1000) + 60000)
            ):
                return
            # The first replay can recover a response lost hours earlier; it does
            # not extend that old access token. A second fresh rotation can then
            # renew it normally, using the recovered current refresh credential.
            for _ in range(2):
                pending = self.data.get("pending_rotation")
                if pending is None:
                    pending = {
                        "rotationId": "rotation_" + uuid4().hex,
                        "nextAccessToken": encode64(secrets.token_bytes(32)),
                        "nextRefreshToken": encode64(secrets.token_bytes(32)),
                    }
                    self.data["pending_rotation"] = pending
                    await self._save()
                self.metrics["renewals"] += 1
                result = await self._raw(
                    "POST", self.connection_path + "/renew", pending, self.data["refresh_token"], "PackInRefresh"
                )
                self.data.update(access_token=pending["nextAccessToken"], refresh_token=pending["nextRefreshToken"])
                self.data.pop("pending_rotation", None)
                await self._merge_metadata(result)
                if self.data.get("access_expires_at_ms", 0) > int(time.time() * 1000) + 60000:
                    return
            raise PackInApiError("session_renewal_failed", 401)

    async def request(self, method: str, suffix: str = "", value: dict[str, Any] | None = None) -> dict[str, Any]:
        await self.ensure_session()
        try:
            return await self._raw(method, self.connection_path + suffix, value, self.data["access_token"])
        except PackInApiError as exc:
            if exc.code != "home_assistant_session_expired":
                raise
            await self.ensure_session(force=True)
            return await self._raw(method, self.connection_path + suffix, value, self.data["access_token"])

    async def metadata(self) -> dict[str, Any]:
        result = await self.request("GET")
        await self._merge_metadata(result)
        return result

    async def refresh_keys(self) -> None:
        result = await self.request("GET", "/keys")
        await self._merge_metadata(result)

    async def request_key(self, epoch: int) -> None:
        if type(epoch) is not int or epoch < 1:
            raise CryptoError("Invalid key epoch")
        self.metrics["key_requests"] += 1
        await self.request("POST", "/keys/request", {"epoch": epoch})

    async def locations(self) -> dict[str, Any]:
        self.metrics["location_batches"] += 1
        return await self.request("GET", "/locations")

    async def websocket(self) -> aiohttp.ClientWebSocketResponse:
        await self.ensure_session()
        epoch = self.data.get("data_epoch")
        if type(epoch) is not int or epoch < 1:
            raise PackInApiError("invalid_data_epoch")
        path = (
            self.connection_path
            + "/realtime?protocolVersion="
            + str(PROTOCOL_VERSION)
            + ("&syncGeneration=" + str(SYNC_GENERATION) + "&dataEpoch=" + str(epoch))
        )
        headers = self._headers("GET", path, b"", self.data["access_token"], "PackInHA")
        self.metrics["websocket_handshakes"] += 1
        self.metrics["http_requests"] += 1
        try:
            return await asyncio.wait_for(
                self.session.ws_connect(
                    self.origin + path,
                    headers=headers,
                    heartbeat=WS_HEARTBEAT,
                    autoping=True,
                    max_msg_size=1_600_000,
                    timeout=aiohttp.ClientWSTimeout(ws_close=10),
                ),
                timeout=20,
            )
        except aiohttp.WSServerHandshakeError as exc:
            raise PackInApiError(
                exc.headers.get("x-packin-ha-error-code", "connection_unavailable")
                if exc.headers
                else "connection_unavailable",
                exc.status,
                self._retry_after(exc.headers.get("retry-after") if exc.headers else None),
            ) from None
        except (asyncio.TimeoutError, aiohttp.ClientError):
            raise PackInApiError("network_unavailable") from None

    async def disconnect(self) -> None:
        # Privacy cleanup stays possible after Premium expires.
        await self._raw("DELETE", self.connection_path, credential=self.data["refresh_token"], scheme="PackInRefresh")

    async def start_pairing(self, pairing: Pairing) -> None:
        self.metrics["pairing_requests"] += 1
        result = await self._raw("POST", PREFIX + "/pairings", pairing.request)
        pairing.expires_at = result["expiresAt"]

    async def pairing_status(self, pairing: Pairing) -> str:
        result = await self._raw(
            "GET",
            PREFIX + "/pairings/" + pairing.request["pairingId"],
            credential=pairing.request["deviceCode"],
            scheme="PackInPairing",
        )
        state = result.get("state")
        if state not in {"pending", "approved", "denied", "claimed"}:
            raise PackInApiError("invalid_pairing_response")
        return state

    async def claim_pairing(self, pairing: Pairing) -> dict[str, Any]:
        if pairing.claim is None:
            pairing.claim = {
                "claimId": "claim_" + uuid4().hex,
                "accessToken": encode64(secrets.token_bytes(32)),
                "refreshToken": encode64(secrets.token_bytes(32)),
            }
        result = await self._raw(
            "POST",
            PREFIX + "/pairings/" + pairing.request["pairingId"] + "/claim",
            pairing.claim,
            pairing.request["deviceCode"],
            "PackInPairing",
        )
        self.data.update(
            connection_id=result["connectionId"],
            identity=pairing.identity.export(),
            access_token=pairing.claim["accessToken"],
            refresh_token=pairing.claim["refreshToken"],
            cache_key=encode64(secrets.token_bytes(32)),
            device_sequence=0,
            reauth_reason=None,
            pending_rotation=None,
        )
        await self._merge_metadata(result)
        current = self.data.get("key_epoch")
        if str(current) not in self.data.get("pack_keys", {}):
            if type(current) is not int or current < 1:
                raise PackInApiError("invalid_key_epoch")
            if pairing.requested_epoch != current:
                await self.request_key(current)
                pairing.requested_epoch = current
            raise PackInApiError("current_pack_key_required")
        return dict(self.data)
