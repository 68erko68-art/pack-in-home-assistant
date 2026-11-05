"""Client HTTP/proof/rotation behavior and signed ephemeral Find Me records."""

import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import time

import aiohttp
from aiohttp import web
import pytest

from packin_pure.api import PackInApi, PackInApiError, install_keys, deny_redirect
from packin_pure.crypto import CryptoError, DeviceIdentity, decode64, encode64, wrap_context, verify
from packin_pure.find_me import decode_locations


@pytest.fixture(autouse=True)
def loopback_transport_only(request):
    # HA blocks sockets by default. Its official fixture opens the constructor;
    # retain the destination guard so these transport tests can reach only loopback.
    import importlib.util

    if importlib.util.find_spec("pytest_homeassistant") is not None:
        request.getfixturevalue("socket_enabled")
        import pytest_socket

        pytest_socket.socket_allow_hosts(["127.0.0.1"])


ID = "ha_" + "1234567890abcdef" * 2
PATH = "/api/ha/v1/connections/" + ID


@asynccontextmanager
async def server(handler):
    application = web.Application()
    application.router.add_route("*", "/{path:.*}", handler)
    runner = web.AppRunner(application)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    try:
        yield "http://127.0.0.1:" + str(port)
    finally:
        await runner.cleanup()


def credentials():
    return {
        "connection_id": ID,
        "access_token": "old-access",
        "refresh_token": "old-refresh",
        "access_expires_at_ms": int(time.time() * 1000) + 3600000,
        "refresh_expires_at_ms": int(time.time() * 1000) + 30 * 86400000,
        "pack_id": "synthetic-pack",
        "data_epoch": 2,
        "scopes": ["tasks:read", "members:read"],
    }


def test_http_device_proof_binds_exact_body_path_method_and_credential():
    async def run():
        identity = DeviceIdentity.generate()
        observed = []

        async def handler(request):
            raw = await request.read()
            value = request.headers["authorization"].split(" ", 1)[1]
            message = "|".join(
                (
                    "pack-in-ha-request",
                    "1",
                    request.method,
                    request.raw_path,
                    request.headers["x-packin-ha-time"],
                    request.headers["x-packin-ha-nonce"],
                    hashlib.sha256(raw).hexdigest(),
                    hashlib.sha256(value.encode()).hexdigest(),
                )
            )
            verify(
                message.encode(),
                decode64(request.headers["x-packin-ha-signature"]),
                identity.public["signingPublicKey"],
            )
            observed.append(request.raw_path)
            return web.json_response({"ok": True})

        async with server(handler) as origin, aiohttp.ClientSession() as session:
            api = PackInApi(session, identity, credentials(), _test_origin=origin)
            assert await api.request("GET", "/keys") == {"ok": True}
            assert observed == [PATH + "/keys"]
            assert api.metrics["http_requests"] == 1

    asyncio.run(run())


def test_rotation_is_checkpointed_coalesced_and_retried_with_same_intent():
    async def run():
        identity = DeviceIdentity.generate()
        requests, saved = [], []

        async def checkpoint(value):
            saved.append(deepcopy(value))

        async def handler(request):
            value = await request.json()
            requests.append(value)
            if len(requests) == 1:
                return web.json_response({"error": {"code": "temporary_failure"}}, status=503)
            assert requests[0] == value
            return web.json_response(
                {
                    "accessExpiresAt": int(time.time() * 1000) + 3600000,
                    "refreshExpiresAt": int(time.time() * 1000) + 30 * 86400000,
                }
            )

        async with server(handler) as origin, aiohttp.ClientSession() as session:
            data = credentials()
            data["access_expires_at_ms"] = 0
            api = PackInApi(session, identity, data, checkpoint, _test_origin=origin)
            with pytest.raises(PackInApiError):
                await api.ensure_session()
            assert saved[0]["pending_rotation"] == requests[0]
            assert api.data["refresh_token"] == "old-refresh"
            await asyncio.gather(*(api.ensure_session() for _ in range(4)))
            assert len(requests) == 2
            assert api.data["refresh_token"] == requests[0]["nextRefreshToken"]
            assert "pending_rotation" not in api.data
            assert "pending_rotation" not in saved[-1]

    asyncio.run(run())


def test_rate_limit_is_preserved_and_redirects_are_not_followed():
    async def run():
        async def handler(request):
            if request.path.endswith("/redirect"):
                return web.Response(status=302, headers={"location": "https://credentials-must-not-leave.invalid/"})
            return web.json_response({"error": {"code": "rate_limited"}}, status=429, headers={"retry-after": "600"})

        async with server(handler) as origin, aiohttp.ClientSession() as session:
            api = PackInApi(session, DeviceIdentity.generate(), credentials(), _test_origin=origin)
            with pytest.raises(PackInApiError) as error:
                await api.request("GET")
            assert error.value.status == 429 and error.value.retry_after == 600
            with pytest.raises(PackInApiError) as error:
                await api.request("GET", "/redirect")
            assert error.value.code == "unexpected_redirect"

    asyncio.run(run())


def test_malformed_error_and_oversized_response_do_not_escape_the_error_boundary():
    async def run():
        async def handler(request):
            if request.path.endswith("/large"):
                return web.Response(body=b"x" * 1000001)
            return web.json_response({"error": "unexpected error shape"}, status=500)

        async with server(handler) as origin, aiohttp.ClientSession() as session:
            api = PackInApi(session, DeviceIdentity.generate(), credentials(), _test_origin=origin)
            with pytest.raises(PackInApiError) as error:
                await api.request("GET")
            assert error.value.code == "request_failed"
            with pytest.raises(PackInApiError) as error:
                await api.request("GET", "/large")
            assert error.value.code == "response_too_large"

    asyncio.run(run())


def test_test_override_cannot_send_credentials_to_an_external_origin():
    async def run():
        async with aiohttp.ClientSession() as session:
            for origin in (
                "https://attacker.invalid",
                "http://127.0.0.1.attacker.invalid",
                "http://user:password@127.0.0.1",
            ):
                with pytest.raises(ValueError):
                    PackInApi(session, DeviceIdentity.generate(), credentials(), _test_origin=origin)

    asyncio.run(run())


def test_wrapped_keys_are_signed_pack_bound_and_immutable():
    phone, hub = DeviceIdentity.generate(), DeviceIdentity.generate()
    context = wrap_context("synthetic-pack", 7)
    wrapped = phone.wrap(b"p" * 32, hub.public["encryptionPublicKey"], context)
    row = {
        "epoch": 7,
        "encryptedKey": encode64(wrapped),
        "signature": encode64(phone.sign(context + wrapped)),
        "senderSigningPublicKey": phone.public["signingPublicKey"],
    }
    installed = install_keys(hub, "synthetic-pack", [row])
    assert decode64(installed["7"]) == b"p" * 32
    with pytest.raises(CryptoError):
        install_keys(hub, "other-pack", [row])
    with pytest.raises(CryptoError):
        install_keys(hub, "synthetic-pack", [row], {"7": encode64(b"x" * 32)})


def location(identity, now, *, user="member", timestamp=None, latitude=64.1, longitude=-21.9, sequence=1):
    observed = timestamp or now
    payload = {
        "schemaVersion": 1,
        "latitude": latitude,
        "longitude": longitude,
        "accuracyMeters": 12,
        "observedAt": observed.isoformat(),
    }
    encoded = identity.encrypt_event(
        json.dumps(payload).encode(),
        b"k" * 32,
        pack="synthetic-pack",
        event="location-" + str(sequence),
        device="synthetic-device",
        sequence=sequence,
        event_type="find_me.location",
        epoch=7,
    )
    return {
        "user_id": user,
        "key_epoch": 7,
        "event_id": "location-" + str(sequence),
        "device_id": "synthetic-device",
        "device_sequence": sequence,
        "observed_at": observed.isoformat(),
        "encrypted_payload": encoded,
        "signing_public_key": identity.public["signingPublicKey"],
    }


def test_locations_require_consent_and_keep_observation_age_separate_from_fetch_time():
    now = datetime.now(timezone.utc)
    row = location(DeviceIdentity.generate(), now, timestamp=now - timedelta(minutes=20))
    assert decode_locations([row], "synthetic-pack", {7: b"k" * 32}, set(), now) == {}
    value = decode_locations([row], "synthetic-pack", {7: b"k" * 32}, {"member"}, now)["member"]
    assert value.age_seconds(now) == 1200
    assert value.synchronized_at == now
    assert value.observed_at != now


def test_location_observation_metadata_cannot_be_forged():
    now = datetime.now(timezone.utc)
    row = location(DeviceIdentity.generate(), now)
    row["observed_at"] = (now + timedelta(seconds=1)).isoformat()
    with pytest.raises(CryptoError):
        decode_locations([row], "synthetic-pack", {7: b"k" * 32}, {"member"}, now)


@pytest.mark.parametrize("latitude,longitude", [(91, 0), (0, -181), (float("nan"), 0), (True, 0)])
def test_invalid_coordinates_do_not_become_a_tracker(latitude, longitude):
    now = datetime.now(timezone.utc)
    row = location(DeviceIdentity.generate(), now, latitude=latitude, longitude=longitude)
    with pytest.raises(CryptoError):
        decode_locations([row], "synthetic-pack", {7: b"k" * 32}, {"member"}, now)


def test_newest_signed_observation_wins_without_fabricating_a_new_observation_time():
    now = datetime.now(timezone.utc)
    who = DeviceIdentity.generate()
    rows = [
        location(who, now, timestamp=now - timedelta(minutes=20), sequence=1),
        location(who, now, timestamp=now - timedelta(minutes=5), sequence=2),
    ]
    result = decode_locations(rows, "synthetic-pack", {7: b"k" * 32}, {"member"}, now)
    assert result["member"].age_seconds(now) == 300


def test_websocket_redirect_never_forwards_device_proof_to_another_endpoint():
    async def run():
        reached = []

        async def trap(request):
            reached.append(request.path)
            return web.Response(status=400)

        async with server(trap) as trap_origin:

            async def redirect(request):
                return web.Response(status=302, headers={"location": trap_origin + "/credential-trap"})

            async with server(redirect) as origin, aiohttp.ClientSession(middlewares=(deny_redirect,)) as session:
                api = PackInApi(session, DeviceIdentity.generate(), credentials(), _test_origin=origin)
                with pytest.raises(PackInApiError) as error:
                    await api.websocket()
                assert error.value.code == "unexpected_redirect"
                assert reached == []

    asyncio.run(run())


def test_websocket_control_ping_keeps_one_connection_without_application_polling(monkeypatch):
    monkeypatch.setattr("packin_pure.api.WS_HEARTBEAT", 0.02)

    async def run():
        ping = asyncio.Event()
        requests = []

        async def handler(request):
            requests.append(request.path)
            ws = web.WebSocketResponse(autoping=False)
            await ws.prepare(request)
            async for message in ws:
                if message.type == aiohttp.WSMsgType.PING:
                    ping.set()
                    await ws.pong(message.data)
                else:
                    raise AssertionError("No application heartbeat or polling is expected")
            return ws

        async with server(handler) as origin, aiohttp.ClientSession(middlewares=(deny_redirect,)) as session:
            api = PackInApi(session, DeviceIdentity.generate(), credentials(), _test_origin=origin)
            ws = await api.websocket()
            receive = asyncio.create_task(ws.receive())
            try:
                await asyncio.wait_for(ping.wait(), 2)
                assert len(requests) == 1 and api.metrics["http_requests"] == 1
            finally:
                receive.cancel()
                await asyncio.gather(receive, return_exceptions=True)
                await ws.close()

    asyncio.run(run())
