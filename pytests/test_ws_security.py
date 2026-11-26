"""Security regressions: REST auth can't be skipped with an Upgrade header, and a charger's
identity can't be taken over by another WebSocket client (browser page, LAN device)."""

from __future__ import annotations

import asyncio
import json
import re

import aiohttp
import pytest
from aiohttp.test_utils import TestClient, TestServer
from fake_charger import FakeCharger

from grizzle_local.config import Settings

from .support import RawCharger, login, make_app, wait_for

SERIAL = "GRD-L0000TEST1"
OTHER = "GRD-L0000TEST2"
AUTH_KEY = "s3cr3t-auth-key"


def _make_server(tmp_path, **overrides):
    return make_app(tmp_path, api_password="pw", **overrides)


@pytest.fixture
async def server(tmp_path):
    async with TestServer(_make_server(tmp_path)) as test_server, TestClient(test_server) as client:
        yield client


async def _start_charger(server, session, auth_key=AUTH_KEY):
    url = f"ws://{server.host}:{server.port}/ocpp1.6/{SERIAL}"
    cp = FakeCharger(url, SERIAL, connectors=2, meter_interval=0.5, auth_key=auth_key)
    await cp.connect(session)
    task = asyncio.create_task(cp.run())
    await asyncio.wait_for(cp.booted.wait(), 10)
    return cp, task


async def _stop_charger(cp, task):
    task.cancel()
    await cp.close()


async def _ws_status(server, session, path, headers=None, auth=None) -> int:
    """Open a raw WebSocket; return 101 on success (then close) or the HTTP rejection status."""
    url = f"ws://{server.host}:{server.port}{path}"
    if auth is not None:
        headers = {**(headers or {}), "Authorization": aiohttp.BasicAuth(*auth).encode()}
    try:
        ws = await session.ws_connect(url, protocols=("ocpp1.6",), headers=headers or {})
    except aiohttp.WSServerHandshakeError as err:
        return err.status
    await ws.close()
    return 101


# --- #1: the Upgrade header must not skip REST authentication -------------------------------

def _protected_routes(app):
    """Every /client and /local route except the public ones, with placeholders filled in."""
    from grizzle_local.api import PUBLIC_PATHS

    routes = set()
    for route in app.router.routes():
        path = route.resource.canonical if route.resource else ""
        if route.method == "HEAD" or not path.startswith(("/client/", "/local/")) or path in PUBLIC_PATHS:
            continue
        routes.add((route.method, re.sub(r"\{[^}]+\}", SERIAL, path)))
    return sorted(routes)


@pytest.mark.parametrize(
    "headers",
    [{"Upgrade": "websocket"}, {"Upgrade": "WebSocket", "Connection": "Upgrade"}],
    ids=["upgrade", "upgrade+connection"],
)
async def test_upgrade_header_does_not_bypass_rest_auth(server, session, headers):
    cp, task = await _start_charger(server, session)  # so station routes would otherwise succeed
    try:
        routes = _protected_routes(server.app)
        assert len(routes) >= 25
        for method, path in routes:
            resp = await server.request(method, path, headers=headers, json={"mode": "Inactive", "action": "Reset"})
            assert resp.status == 401, f"{method} {path} with {headers} -> {resp.status}"
        assert server.app["controller"].is_online(SERIAL)
    finally:
        await _stop_charger(cp, task)


async def test_upgrade_header_does_not_mint_tokens(server):
    tokens = server.app["controller"].store.state["tokens"]
    before = len(tokens)
    for _ in range(5):
        await server.get("/client/auth/profile", headers={"Upgrade": "websocket"})
    assert len(tokens) == before


# --- #2: charger identity takeover -----------------------------------------------------------


@pytest.mark.parametrize("origin", [{"Origin": "http://evil.example"}, {"origin": "null"}])
async def test_browser_origin_is_refused(server, session, origin):
    status = await _ws_status(server, session, "/ocpp1.6/GRD-BROWSER1", headers=origin, auth=("x", "y"))
    assert status == 403
    assert server.app["controller"].station("GRD-BROWSER1") is None


@pytest.mark.parametrize(
    "path,user",
    [
        ("/ocpp1.6/bad%0Did", None),  # CR in the path tail
        ("/ocpp1.6/" + "A" * 65, None),  # too long
        ("/ocpp1.6/a%20b", None),  # space
        ("/ocpp1.6", "Z\n2026-11-11 FORGED"),  # newline in the Basic-auth user
        ("/ocpp1.6", "."),  # not addressable through the REST API
        ("/ocpp1.6", ".."),
        ("/ocpp1.6", "-leading-dash"),
    ],
)
async def test_invalid_charge_point_id_is_refused(server, session, path, user):
    auth = (user, "key") if user is not None else None
    status = await _ws_status(server, session, path, auth=auth)
    assert status == 400
    assert server.app["controller"].stations == {}


async def test_pinned_key_rejects_impostor_and_keeps_real_charger(server, session):
    controller = server.app["controller"]
    cp, task = await _start_charger(server, session)
    try:
        real_conn = controller.connections[SERIAL]
        assert controller.station(SERIAL)["ocppAuthKey"] == AUTH_KEY

        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, "attacker-key")) == 401
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}") == 401  # no credentials at all
        assert await _ws_status(server, session, "/ocpp1.6", auth=(SERIAL, "attacker-key")) == 401  # id via user
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, "é")) == 401  # non-ASCII

        await asyncio.sleep(0.2)
        assert controller.connections[SERIAL] is real_conn, "the real charger was displaced"
        assert not cp.ws.closed
        assert controller.station(SERIAL)["ocppAuthKey"] == AUTH_KEY
    finally:
        await _stop_charger(cp, task)


async def test_pinned_key_rejected_even_when_charger_offline(server, session):
    controller = server.app["controller"]
    cp, task = await _start_charger(server, session)
    await _stop_charger(cp, task)
    await wait_for(lambda: not controller.is_online(SERIAL))

    assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, "attacker-key")) == 401
    assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}") == 401
    assert controller.station(SERIAL)["ocppAuthKey"] == AUTH_KEY


async def test_reconnect_with_same_key_replaces_stale_socket(server, session):
    """A real charger reconnecting without closing its old socket must still get in."""
    controller = server.app["controller"]
    cp1, task1 = await _start_charger(server, session)
    old_conn = controller.connections[SERIAL]
    cp2, task2 = await _start_charger(server, session)
    try:
        assert controller.connections[SERIAL] is not old_conn
        await wait_for(lambda: cp1.ws.closed)
    finally:
        await _stop_charger(cp2, task2)
        await _stop_charger(cp1, task1)


async def test_unauthenticated_connection_cannot_displace_live_charger(server, session):
    """A charger that never presented a key can't be pinned, but it still can't be displaced."""
    controller = server.app["controller"]
    cp, task = await _start_charger(server, session, auth_key="")
    try:
        assert not controller.station(SERIAL).get("ocppAuthKey")
        real_conn = controller.connections[SERIAL]
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}") == 409
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, "")) == 409
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, "some-key")) == 409
        assert controller.connections[SERIAL] is real_conn
        assert not controller.station(SERIAL).get("ocppAuthKey")
    finally:
        await _stop_charger(cp, task)


async def test_new_station_without_key_can_still_onboard(server, session):
    assert await _ws_status(server, session, "/ocpp1.6/GRD-NEW00001") == 101
    assert server.app["controller"].station("GRD-NEW00001") is not None


async def test_global_ocpp_password(tmp_path, session):
    app = _make_server(tmp_path, ocpp_password="shared-pw")
    async with TestServer(app) as test_server, TestClient(test_server) as server:
        assert await _ws_status(server, session, "/ocpp1.6/GRD-A0000001") == 401
        assert await _ws_status(server, session, "/ocpp1.6/GRD-A0000001", auth=("GRD-A0000001", "nope")) == 401
        assert await _ws_status(server, session, "/ocpp1.6/GRD-A0000001", auth=("GRD-A0000001", "é")) == 401
        assert await _ws_status(server, session, "/ocpp1.6/GRD-A0000001", auth=("GRD-A0000001", "shared-pw")) == 101


async def test_changing_global_password_does_not_lock_chargers_out(tmp_path, session):
    async with TestServer(_make_server(tmp_path, ocpp_password="old-pw")) as ts, TestClient(ts) as server:
        assert await _ws_status(server, session, "/ocpp1.6/GRD-ROT00001", auth=("GRD-ROT00001", "old-pw")) == 101
    async with TestServer(_make_server(tmp_path, ocpp_password="new-pw")) as ts, TestClient(ts) as server:
        assert await _ws_status(server, session, "/ocpp1.6/GRD-ROT00001", auth=("GRD-ROT00001", "old-pw")) == 401
        assert await _ws_status(server, session, "/ocpp1.6/GRD-ROT00001", auth=("GRD-ROT00001", "new-pw")) == 101
        # The recorded key follows the password (firmware_capture reads it).
        assert server.app["controller"].station("GRD-ROT00001")["ocppAuthKey"] == "new-pw"


async def test_pin_is_saved_immediately_and_survives_restart(tmp_path, session):
    async with TestServer(_make_server(tmp_path)) as ts, TestClient(ts) as server:
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, AUTH_KEY)) == 101
        # On disk before any tick or shutdown save: a crash right now must not lose the pin.
        on_disk = json.loads((tmp_path / "data" / "state.json").read_text())
        assert on_disk["stations"][SERIAL]["ocppAuthKey"] == AUTH_KEY
    async with TestServer(_make_server(tmp_path)) as ts, TestClient(ts) as server:
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, "attacker-key")) == 401
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, AUTH_KEY)) == 101


async def test_stale_socket_without_key_is_replaced(server, session, monkeypatch):
    """A keyless charger reconnecting while its dead old socket is still open must get back in."""
    controller = server.app["controller"]
    monkeypatch.setattr(type(controller), "LIVENESS_TIMEOUT", 0.3)
    url = f"ws://{server.host}:{server.port}/ocpp1.6/{SERIAL}"
    stale = await session.ws_connect(url, protocols=("ocpp1.6",))  # never reads, never answers
    try:
        await wait_for(lambda: controller.is_online(SERIAL))
        old_conn = controller.connections[SERIAL]
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}") == 101
        assert controller.connections.get(SERIAL) is not old_conn
    finally:
        await stale.close()


async def test_keyless_station_is_not_pinned_by_a_later_key(server, session):
    """Someone presenting a key while a keyless charger is offline must not lock it out."""
    controller = server.app["controller"]
    assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}") == 101  # the real, keyless charger
    await wait_for(lambda: not controller.is_online(SERIAL))
    assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, "squatter")) == 101
    assert not controller.station(SERIAL).get("ocppAuthKey")
    await wait_for(lambda: not controller.is_online(SERIAL))
    assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}") == 101  # still gets in


async def test_first_key_on_new_serial_is_pinned(server, session):
    """Trust on first use: whoever connects first under an unseen serial with a key owns it."""
    controller = server.app["controller"]
    assert await _ws_status(server, session, "/ocpp1.6/GRD-NEW00002", auth=("GRD-NEW00002", "first")) == 101
    await wait_for(lambda: not controller.is_online("GRD-NEW00002"))
    assert await _ws_status(server, session, "/ocpp1.6/GRD-NEW00002", auth=("GRD-NEW00002", "second")) == 401


async def test_clear_pinned_key_requires_auth_and_allows_new_key(server, session):
    controller = server.app["controller"]
    cp, task = await _start_charger(server, session)
    await _stop_charger(cp, task)
    await wait_for(lambda: not controller.is_online(SERIAL))

    resp = await server.delete(f"/local/stations/{SERIAL}/auth-key")
    assert resp.status == 401
    resp = await server.delete(f"/local/stations/{SERIAL}/auth-key", headers={"Upgrade": "websocket"})
    assert resp.status == 401
    assert controller.station(SERIAL)["ocppAuthKey"] == AUTH_KEY

    token = (await login(server, password="pw"))["token"]
    resp = await server.delete(f"/local/stations/{SERIAL}/auth-key", headers={"Authorization": f"Bearer {token}"})
    assert resp.status == 200
    assert not controller.station(SERIAL).get("ocppAuthKey")

    cp, task = await _start_charger(server, session, auth_key="new-key")
    try:
        assert controller.station(SERIAL)["ocppAuthKey"] == "new-key"
    finally:
        await _stop_charger(cp, task)


async def test_clear_pinned_key_drops_live_connection_so_charger_repins(server, session):
    controller = server.app["controller"]
    cp, task = await _start_charger(server, session)
    try:
        token = (await login(server, password="pw"))["token"]
        resp = await server.delete(f"/local/stations/{SERIAL}/auth-key", headers={"Authorization": f"Bearer {token}"})
        assert resp.status == 200
        await wait_for(lambda: cp.ws.closed)
        on_disk = json.loads((controller.store._state_path).read_text())
        assert "ocppAuthKey" not in on_disk["stations"][SERIAL]
    finally:
        await _stop_charger(cp, task)
    cp, task = await _start_charger(server, session, auth_key="rotated-key")
    try:
        assert controller.station(SERIAL)["ocppAuthKey"] == "rotated-key"
    finally:
        await _stop_charger(cp, task)


async def test_concurrent_first_connections_cannot_both_get_in(server, session, monkeypatch):
    """Two first connections for an unpinned serial race between the check and the install:
    only one may get in, and the installed connection must be the one whose key is pinned."""
    controller = server.app["controller"]
    original = type(controller).connection_refusal

    async def slow_refusal(self, cp_id, auth_key):
        result = await original(self, cp_id, auth_key)
        await asyncio.sleep(0.3)  # widen the window between the check and on_connect
        return result

    monkeypatch.setattr(type(controller), "connection_refusal", slow_refusal)
    url = f"ws://{server.host}:{server.port}/ocpp1.6/GRD-RACE0001"

    async def attempt(key):
        auth = {"Authorization": aiohttp.BasicAuth("GRD-RACE0001", key).encode()}
        try:
            return key, await session.ws_connect(url, protocols=("ocpp1.6",), headers=auth)
        except aiohttp.WSServerHandshakeError as err:
            return key, err.status

    results = await asyncio.gather(attempt("key-a"), attempt("key-b"))
    winners = [(k, r) for k, r in results if not isinstance(r, int)]
    try:
        assert len(winners) == 1, results
        assert sorted(r for _, r in results if isinstance(r, int)) == [401]
        assert controller.station("GRD-RACE0001")["ocppAuthKey"] == winners[0][0]
        assert controller.is_online("GRD-RACE0001")
        assert controller._admission_locks == {}
    finally:
        for _, ws in winners:
            await ws.close()


# --- #3: GRIZZLE_ALLOWED_CHARGERS, the serials that may connect at all -------------------------------


def test_allowed_chargers_setting(monkeypatch):
    assert Settings().allowed_chargers == ()
    monkeypatch.setenv("GRIZZLE_ALLOWED_CHARGERS", f" {SERIAL},{OTHER}  unknown-192.168.1.50 ")
    assert Settings().allowed_chargers == (SERIAL, OTHER, "unknown-192.168.1.50")
    monkeypatch.setenv("GRIZZLE_ALLOWED_CHARGERS", " , ")
    assert Settings().allowed_chargers == ()  # blank: no list, any serial may connect
    assert Settings(allowed_chargers=[SERIAL]).allowed_chargers == (SERIAL,)
    # An entry no charger could ever present (quotes kept by a compose list, say) is an error at
    # startup rather than a charger that is silently never let in.
    for impossible in (f'"{SERIAL}"', f"{SERIAL};", "*", "-GRD", "x" * 65):
        with pytest.raises(ValueError, match="GRIZZLE_ALLOWED_CHARGERS.*leave it unset"):
            Settings(allowed_chargers=impossible)
    # The name a charger without an id is given can be listed, but it is not a serial: say so.
    placeholder = Settings(allowed_chargers=f"{SERIAL} unknown-192.168.1.50", api_password="a long passphrase")
    assert ["unknown-192.168.1.50" in w and SERIAL not in w for w in placeholder.security_warnings()] == [True]
    assert not Settings(allowed_chargers=SERIAL, api_password="a long passphrase").security_warnings()


@pytest.mark.parametrize("blank", ["", " , "])
async def test_a_blank_list_lets_any_serial_connect(tmp_path, session, monkeypatch, blank):
    monkeypatch.setenv("GRIZZLE_ALLOWED_CHARGERS", blank)  # in compose: GRIZZLE_ALLOWED_CHARGERS: ""
    async with TestServer(_make_server(tmp_path)) as ts, TestClient(ts) as server:
        assert await _ws_status(server, session, f"/ocpp1.6/{OTHER}") == 101


async def test_only_listed_serials_may_connect(tmp_path, session, caplog):
    app = _make_server(tmp_path, allowed_chargers=f"{SERIAL}, {OTHER}")
    async with TestServer(app) as ts, TestClient(ts) as server:
        controller = server.app["controller"]
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, AUTH_KEY)) == 101
        assert await _ws_status(server, session, f"/ocpp1.6/{OTHER}") == 101
        # Not listed: near misses, another spelling, and the name given to a charger that sends no serial.
        for stranger in ("GRD-L0000TEST3", SERIAL.lower(), SERIAL[:-1], SERIAL + "1", "unknown-127.0.0.1"):
            assert await _ws_status(server, session, f"/ocpp1.6/{stranger}") == 401, stranger
        # However the serial is given: as the HTTP Basic user, or not at all. And the serial in the
        # path is the one that counts: a listed Basic user does not let another serial in.
        assert await _ws_status(server, session, "/ocpp1.6", auth=("GRD-L0000TEST3", "key")) == 401
        assert await _ws_status(server, session, "/ocpp1.6") == 401
        assert await _ws_status(server, session, "/ocpp1.6/GRD-L0000TEST3", auth=(SERIAL, AUTH_KEY)) == 401
        await wait_for(lambda: not controller.is_online(OTHER))
        assert await _ws_status(server, session, "/ocpp1.6", auth=(OTHER, "")) == 101
        assert set(controller.stations) == {SERIAL, OTHER}  # nothing was kept for the others
    assert "GRD-L0000TEST3: rejected connection" in caplog.text and "GRIZZLE_ALLOWED_CHARGERS" in caplog.text


async def test_a_listed_serial_still_needs_its_key(tmp_path, session):
    """The list keeps other serials out. A serial is printed on the charger and anyone can present
    it: what keeps someone else from being taken for a listed charger is still its key."""
    async with TestServer(_make_server(tmp_path, allowed_chargers=SERIAL)) as ts, TestClient(ts) as server:
        cp, task = await _start_charger(server, session)  # the real one; its key is pinned
        try:
            assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}") == 401
            assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, "a guess")) == 401
            assert server.app["controller"].is_online(SERIAL)
        finally:
            await _stop_charger(cp, task)
        await wait_for(lambda: not server.app["controller"].is_online(SERIAL))
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, "a guess")) == 401
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, AUTH_KEY)) == 101


async def test_a_listed_charger_without_a_key_cannot_be_displaced_while_it_answers(tmp_path, session):
    """A charger that sends no key has only its serial. Listed or not, whoever else presents that
    serial is refused for as long as the charger is connected and answering."""
    async with TestServer(_make_server(tmp_path, allowed_chargers=OTHER)) as ts, TestClient(ts) as server:
        controller = server.app["controller"]
        async with await RawCharger.connect(server, session, OTHER):
            await wait_for(lambda: controller.is_online(OTHER))
            real = controller.connections[OTHER]
            assert await _ws_status(server, session, f"/ocpp1.6/{OTHER}") == 409
            assert await _ws_status(server, session, f"/ocpp1.6/{OTHER}", auth=(OTHER, "a guess")) == 409
            assert controller.connections[OTHER] is real


async def test_the_station_limit_still_applies_to_listed_serials(tmp_path, session):
    app = _make_server(tmp_path, allowed_chargers=f"{SERIAL},{OTHER}", max_stations=1)
    async with TestServer(app) as ts, TestClient(ts) as server:
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}") == 101
        assert await _ws_status(server, session, f"/ocpp1.6/{OTHER}") == 503


async def test_a_charger_that_sends_no_id_can_be_listed_by_the_name_it_is_given(tmp_path, session):
    async with TestServer(_make_server(tmp_path, allowed_chargers="unknown-127.0.0.1")) as ts, TestClient(ts) as server:
        assert await _ws_status(server, session, "/ocpp1.6") == 101
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}") == 401


async def test_the_list_applies_with_a_shared_ocpp_password_too(tmp_path, session):
    app = _make_server(tmp_path, allowed_chargers=SERIAL, ocpp_password="shared-pw")
    async with TestServer(app) as ts, TestClient(ts) as server:
        assert await _ws_status(server, session, f"/ocpp1.6/{OTHER}", auth=(OTHER, "shared-pw")) == 401
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, "wrong")) == 401
        assert await _ws_status(server, session, f"/ocpp1.6/{SERIAL}", auth=(SERIAL, "shared-pw")) == 101
        assert set(server.app["controller"].stations) == {SERIAL}


async def test_a_station_left_off_the_list_is_kept_but_cannot_connect(tmp_path, session):
    async with TestServer(_make_server(tmp_path)) as ts, TestClient(ts) as server:  # no list yet
        assert await _ws_status(server, session, f"/ocpp1.6/{OTHER}") == 101
    async with TestServer(_make_server(tmp_path, allowed_chargers=SERIAL)) as ts, TestClient(ts) as server:
        assert await _ws_status(server, session, f"/ocpp1.6/{OTHER}") == 401
        assert OTHER in server.app["controller"].stations


async def test_a_pinned_station_left_off_the_list_cannot_connect_with_its_own_key(tmp_path, session):
    """A charger that registered before the list existed presents the right key: the list still decides."""
    async with TestServer(_make_server(tmp_path)) as ts, TestClient(ts) as server:  # no list yet
        assert await _ws_status(server, session, f"/ocpp1.6/{OTHER}", auth=(OTHER, AUTH_KEY)) == 101
    async with TestServer(_make_server(tmp_path, allowed_chargers=SERIAL)) as ts, TestClient(ts) as server:
        assert await _ws_status(server, session, f"/ocpp1.6/{OTHER}", auth=(OTHER, AUTH_KEY)) == 401
        assert server.app["controller"].station(OTHER)["ocppAuthKey"] == AUTH_KEY  # kept, pin and all
        assert not server.app["controller"].is_online(OTHER)
