"""The REST API and the web page: sign-in, sessions, input validation, what is disclosed to whom."""

from __future__ import annotations

import json
import logging
import stat
import time

import aiohttp
import pytest
from aiohttp.test_utils import TestClient, TestServer

from grizzle_local import api as api_module
from grizzle_local.api import LoginThrottle
from grizzle_local.config import Settings, frame_ancestors
from grizzle_local.controller import MAX_CONNECTORS, MAX_ZONES
from grizzle_local.schedules import normalize_zone, zone_id

from .support import EMAIL, PASSWORD, RawCharger, bearer, login, make_app, strict_json

SERIAL = "GRD-L0000HARD2"


@pytest.fixture
async def server(tmp_path):
    async with TestServer(make_app(tmp_path)) as test_server, TestClient(test_server) as client:
        yield client


@pytest.fixture
async def session():
    async with aiohttp.ClientSession() as s:
        yield s


@pytest.fixture
async def station(server):
    """A station that exists (and is offline), with a signed-in client: (client, headers, station dict)."""
    controller = server.app["controller"]
    controller._ensure_station(SERIAL)
    return server, await bearer(server), controller.station(SERIAL)


def _tokens(client) -> dict:
    return client.app["controller"].store.state["tokens"]


# --- signing in ---------------------------------------------------------------------------------


@pytest.mark.parametrize("password", ["pöö", "密码", "\udcff", "x" * 100_000, "", None, 12345, ["a"], {"a": 1}])
async def test_login_with_any_wrong_password_is_a_plain_401(server, password):
    """compare_digest() refuses non-ASCII str: the right email with such a password was a 500,
    which also told the caller the email was right."""
    resp = await server.post("/client/auth/login", json={"emailOrPhone": EMAIL, "password": password})
    assert resp.status == 401
    assert (await resp.json())["message"] == "Invalid email or password"
    resp = await server.post("/client/auth/login", json={"emailOrPhone": "who@else", "password": password})
    assert resp.status == 401


async def test_non_ascii_password_can_be_the_right_one(tmp_path):
    async with TestServer(make_app(tmp_path, api_password="pässwörd-密码")) as ts, TestClient(ts) as client:
        resp = await client.post("/client/auth/login", json={"emailOrPhone": EMAIL, "password": "passwoerd"})
        assert resp.status == 401
        await login(client, password="pässwörd-密码")


@pytest.mark.parametrize("token", ["é", "\udcff", "x" * 100_000, "", None, 5, ["a"]])
async def test_refresh_with_a_bogus_token_is_a_plain_401(server, token):
    await login(server)  # so there is a session to compare against
    resp = await server.post("/client/auth/refresh-token", json={"refreshToken": token})
    assert resp.status == 401


@pytest.mark.parametrize("body", ["[" * 100_000, '{"emailOrPhone": ', "\xff\xfe", "[]", '"text"', "12"])
async def test_malformed_login_bodies_are_client_errors(server, body):
    headers = {"Content-Type": "application/json"}
    resp = await server.post("/client/auth/login", data=body.encode("latin-1"), headers=headers)
    assert resp.status in (400, 401), resp.status


async def test_an_empty_configured_password_lets_nobody_in(tmp_path):
    settings = Settings(data_dir=tmp_path / "data", api_email=EMAIL, api_password="")
    assert any("empty" in warning for warning in settings.security_warnings())
    async with TestServer(make_app(tmp_path, api_password="")) as ts, TestClient(ts) as client:
        for password in ("", None, " "):
            resp = await client.post("/client/auth/login", json={"emailOrPhone": EMAIL, "password": password})
            assert resp.status == 401


def test_startup_warnings_name_weak_passwords():
    def warnings(**kw):
        return " ".join(Settings(**kw).security_warnings())

    assert "well-known default" in warnings()  # the built-in default
    assert "well-known default" in warnings(api_password="change-me")  # what docker-compose.yml ships
    assert "shorter than 8" in warnings(api_password="abc")
    assert warnings(api_password="a long passphrase of my own") == ""
    assert "clickjacking" in warnings(api_password="a long passphrase of my own", frame_ancestors="*")


async def test_password_guessing_is_throttled(server):
    for _ in range(api_module.LOGIN_MAX_FAILURES):
        resp = await server.post("/client/auth/login", json={"emailOrPhone": EMAIL, "password": "guess"})
        assert resp.status == 401
    resp = await server.post("/client/auth/login", json={"emailOrPhone": EMAIL, "password": "guess"})
    assert resp.status == 429
    assert 0 < int(resp.headers["Retry-After"]) <= api_module.LOGIN_WINDOW_SECONDS
    # Even the right password has to wait now: otherwise the limit would only slow down wrong guesses.
    resp = await server.post("/client/auth/login", json={"emailOrPhone": EMAIL, "password": PASSWORD})
    assert resp.status == 429
    # Sessions that already exist are not affected.
    assert (await server.post("/client/auth/refresh-token", json={"refreshToken": "nope"})).status == 401


async def test_a_successful_login_clears_the_failures(server):
    for _ in range(api_module.LOGIN_MAX_FAILURES - 1):
        await server.post("/client/auth/login", json={"emailOrPhone": EMAIL, "password": "guess"})
    await login(server)
    for _ in range(api_module.LOGIN_MAX_FAILURES - 1):
        resp = await server.post("/client/auth/login", json={"emailOrPhone": EMAIL, "password": "guess"})
        assert resp.status == 401


def test_login_throttle_window_and_bounds():
    throttle = LoginThrottle(max_failures=3, window=100)
    for moment in (0, 10, 20):
        assert throttle.retry_after("10.0.0.9", now=moment) == 0
        throttle.failed("10.0.0.9", now=moment)
    assert throttle.retry_after("10.0.0.9", now=21) == 79  # until the oldest failure leaves the window
    assert throttle.retry_after("10.0.0.7", now=21) == 0  # somebody else is not affected
    assert throttle.retry_after("10.0.0.9", now=100.5) == 0  # the first failure has aged out
    throttle.failed("10.0.0.9", now=101)
    assert throttle.retry_after("10.0.0.9", now=101) == 9
    throttle.succeeded("10.0.0.9")
    assert throttle.retry_after("10.0.0.9", now=102) == 0

    throttle = LoginThrottle()
    for n in range(LoginThrottle.MAX_CLIENTS + 500):  # addresses are cheap to invent (IPv6)
        throttle.failed(f"client-{n}")
    assert len(throttle._failures) == LoginThrottle.MAX_CLIENTS


# --- sessions -------------------------------------------------------------------------------------


async def test_profile_does_not_mint_tokens(server):
    headers = await bearer(server)
    before = dict(_tokens(server))
    for _ in range(10):
        resp = await server.get("/client/auth/profile", headers=headers)
        assert resp.status == 200 and (await resp.json())["email"] == EMAIL
    assert _tokens(server) == before


async def test_logout_ends_the_session_on_the_server(server):
    tokens = await login(server)
    headers = {"Authorization": f"Bearer {tokens['token']}"}
    assert (await server.get("/client/stations", headers=headers)).status == 200
    assert (await server.post("/client/auth/logout", headers=headers)).status == 200
    assert (await server.get("/client/stations", headers=headers)).status == 401
    resp = await server.post("/client/auth/refresh-token", json={"refreshToken": tokens["refreshToken"]})
    assert resp.status == 401
    assert (await server.post("/client/auth/logout")).status == 401  # and logging out needs a session


async def test_the_web_page_signs_out_on_the_server_too(server):
    html = await (await server.get("/")).text()
    assert '"/client/auth/logout"' in html


async def test_token_in_the_query_string_is_not_accepted(server):
    token = (await login(server))["token"]
    assert (await server.get(f"/client/stations?token={token}")).status == 401
    assert (await server.get("/client/stations", headers={"Authorization": f"Bearer {token}"})).status == 200
    assert (await server.get("/client/stations", headers={"Authorization": f"bearer  {token} "})).status == 200


async def test_the_number_of_sessions_is_bounded(server, monkeypatch):
    monkeypatch.setattr(api_module, "MAX_TOKENS", 5)
    issued = [(await login(server))["token"] for _ in range(8)]
    assert len(_tokens(server)) == 5
    assert set(_tokens(server)) == set(issued[-5:])  # the oldest made room


async def test_refresh_tokens_expire(server):
    tokens = await login(server)
    info = _tokens(server)[tokens["token"]]
    assert info["refreshExpires"] - info["expires"] == pytest.approx(api_module.REFRESH_TTL - api_module.TOKEN_TTL)

    info["expires"] = time.time() - 10  # the access token has run out; the refresh token has not
    assert (await server.get("/client/stations", headers={"Authorization": f"Bearer {tokens['token']}"})).status == 401
    resp = await server.post("/client/auth/refresh-token", json={"refreshToken": tokens["refreshToken"]})
    assert resp.status == 200
    renewed = await resp.json()

    # Once the refresh token itself has expired it is worthless, and it used to work forever
    # (until someone else happened to sign in and garbage-collect it).
    _tokens(server)[renewed["token"]]["refreshExpires"] = time.time() - 10
    resp = await server.post("/client/auth/refresh-token", json={"refreshToken": renewed["refreshToken"]})
    assert resp.status == 401
    assert _tokens(server) == {}


async def test_sessions_saved_by_an_older_version_still_work(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    old = {"token-from-before": {"refresh": "refresh-from-before", "expires": time.time() + 3600}}
    (data / "state.json").write_text(json.dumps({"tokens": old, "stations": {}}))
    async with TestServer(make_app(tmp_path)) as ts, TestClient(ts) as client:
        resp = await client.get("/client/stations", headers={"Authorization": "Bearer token-from-before"})
        assert resp.status == 200
        resp = await client.post("/client/auth/refresh-token", json={"refreshToken": "refresh-from-before"})
        assert resp.status == 200


# --- what the public endpoints say -----------------------------------------------------------------


async def test_health_does_not_list_serials_to_strangers(server, session):
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        resp = await server.get("/health")
        assert resp.status == 200
        text = await resp.text()
        data = strict_json(text)
        assert SERIAL not in text and "stations" not in data
        assert data["status"] == "ok" and data["stationCount"] == 1 and data["stationsOnline"] == 1
        signed_in = await (await server.get("/health", headers=await bearer(server))).json()
        assert signed_in["stations"] == {SERIAL: True}
    finally:
        await cp.close()


@pytest.mark.parametrize("serial", ["GRD%0AINFO%20forged", "a%20b", "-dash", "x" * 65, "%00", "..", "é"])
async def test_unlock_check_ignores_things_that_are_not_serials(server, serial, caplog):
    caplog.set_level(logging.INFO)
    resp = await server.get(f"/commercial/ext-ocpp-check/{serial}")
    assert resp.status == 404
    ours = [r for r in caplog.records if r.name.startswith("grizzle_local")]  # not aiohttp's test-only access log
    assert not [r for r in ours if "ext-ocpp-check" in r.getMessage()]


def test_frame_ancestors_setting(monkeypatch):
    assert Settings().frame_ancestors == "'self'"
    monkeypatch.setenv("GRIZZLE_FRAME_ANCESTORS", "http://homeassistant.local:8123, https://ha.example.com")
    assert Settings().frame_ancestors == "http://homeassistant.local:8123 https://ha.example.com"
    for value in ("x; script-src *", '"self"', "http://a/b", "'unsafe-inline'", "a\tb;c"):
        with pytest.raises(ValueError):
            frame_ancestors(value)
        with pytest.raises(ValueError):
            Settings(frame_ancestors=value)
    assert frame_ancestors("*") == "*" and frame_ancestors(" 'none' ") == "'none'"


async def test_page_is_not_frameable_by_other_sites_unless_configured(tmp_path):
    async with TestServer(make_app(tmp_path)) as ts, TestClient(ts) as client:
        resp = await client.get("/")
        policy = resp.headers["Content-Security-Policy"]
        assert policy.endswith("frame-ancestors 'self'") and "frame-ancestors *" not in policy
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["Referrer-Policy"] == "no-referrer"
    app = make_app(tmp_path, frame_ancestors="http://homeassistant.local:8123")
    async with TestServer(app) as ts, TestClient(ts) as client:
        policy = (await client.get("/")).headers["Content-Security-Policy"]
        assert policy.endswith("frame-ancestors http://homeassistant.local:8123")


# --- parameters -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/client/stations/{id}/events?limit=abc",
        "/client/stations/{id}/events?limit=0",
        "/client/stations/{id}/events?limit=--5",
        "/client/stations/{id}/events?limit=99999999999999999999",
        "/local/stations/{id}/sessions?limit=1e3",
        "/local/stations/{id}/sessions?limit=-1",
        "/local/stations/{id}/samples?connector=abc",
        "/local/stations/{id}/samples?connector=999999",
        "/local/stations/{id}/samples?since=yesterday",
        "/local/stations/{id}/samples?since=9999-12-31T23:59:59-23:59",
    ],
)
async def test_bad_query_parameters_are_400_not_500(station, path):
    client, headers, _ = station
    resp = await client.get(path.format(id=SERIAL), headers=headers)
    assert resp.status == 400, await resp.text()
    assert "message" in await resp.json()


async def test_good_query_parameters_still_work(station):
    client, headers, _ = station
    for path in ("events", "events?limit=5", "events?limit=1000"):
        assert (await client.get(f"/client/stations/{SERIAL}/{path}", headers=headers)).status == 200
    for path in ("sessions?limit=5", "samples", "samples?connector=1", "samples?since=2026-11-08T00:00:00Z",
                 "samples?since=2026-11-08T02:00:00%2B02:00&connector=2"):
        assert (await client.get(f"/local/stations/{SERIAL}/{path}", headers=headers)).status == 200


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("PUT", "/client/stations/{id}/currentLimit", {"value": "lots"}),
        ("PUT", "/client/stations/{id}/currentLimit", {"value": 1e999}),
        ("PUT", "/client/stations/{id}/currentLimit", {"value": None}),
        ("PUT", "/client/stations/{id}/currentLimit", {"value": [16]}),
        ("PUT", "/client/stations/{id}/currentLimit", {}),
        ("PUT", "/client/stations/{id}/rate", {"priceKW": float("nan")}),
        ("PUT", "/client/stations/{id}/rate", {"priceKW": float("inf")}),
        ("PUT", "/client/stations/{id}/rate", {"priceKW": "NaN"}),
        ("PUT", "/client/stations/{id}/rate", {"priceKW": -0.1}),
        ("PUT", "/client/stations/{id}/rate", {"priceKW": True}),
        ("PUT", "/client/stations/{id}/rate", {"priceKW": {"a": 1}}),
        ("POST", "/client/stations/{id}/mode", {"mode": "Active", "connectorId": 99}),
        ("POST", "/client/stations/{id}/mode", {"mode": "Active", "connectorId": 2}),  # the station has one
        ("POST", "/client/stations/{id}/mode", {"mode": "Active", "connectorId": "one"}),
        ("POST", "/client/stations/{id}/mode", {"mode": ["Active"], "connectorId": 1}),
        ("POST", "/local/stations/{id}/ocpp", {"action": "Reset", "timeout": "soon"}),
        ("POST", "/local/stations/{id}/ocpp", {"action": "Reset", "timeout": float("nan")}),
        ("POST", "/local/stations/{id}/ocpp", {"action": "Reset", "timeout": 1e9}),
        ("POST", "/local/stations/{id}/ocpp", {"action": "Reset", "timeout": -1}),
        ("POST", "/local/stations/{id}/ocpp", {"action": "Reset", "payload": [1]}),
        ("POST", "/local/stations/{id}/ocpp", {"action": "Reset", "payload": {"x": float("nan")}}),
        ("POST", "/local/stations/{id}/ocpp", {"action": "x" * 100}),
        ("POST", "/local/stations/{id}/ocpp", {"action": 5}),
        ("PUT", "/local/stations/{id}/holidays", {"enabled": True, "country": 12}),
        ("PUT", "/local/stations/{id}/holidays", {"priceKW": float("nan")}),
        ("PUT", "/local/stations/{id}/holidays", {"priceKW": [1]}),
        ("PUT", "/local/stations/{id}/holidays", {"excludedNames": "Christmas Day"}),
        ("PUT", "/local/stations/{id}/holidays", {"excludedNames": [5]}),
        ("PUT", "/local/stations/{id}/holidays", {"extraDates": [{"date": "2026-12-24"}] * 501}),
        ("POST", "/local/stations/{id}/holidays/preview", {"extraDates": {"date": "2026-12-24"}}),
    ],
)
async def test_bad_bodies_are_400_and_change_nothing(station, method, path, body):
    client, headers, state = station
    before = json.dumps(state, sort_keys=True)
    resp = await client.request(method, path.format(id=SERIAL), data=json.dumps(body), headers=headers)
    assert resp.status == 400, f"{resp.status} {await resp.text()}"
    assert "message" in strict_json(await resp.text())
    assert json.dumps(state, sort_keys=True) == before


async def test_raw_ocpp_call_validates_but_still_reaches_an_offline_error(station):
    client, headers, _ = station
    resp = await client.post(f"/local/stations/{SERIAL}/ocpp", json={"action": "Reset", "timeout": 2}, headers=headers)
    assert resp.status == 502 and (await resp.json())["error"] == "Offline"


# --- station settings ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "patch",
    [
        {"connectorCount": 1_000_000},
        {"connectorCount": MAX_CONNECTORS + 1},
        {"connectorCount": 0},
        {"connectorCount": None},
        {"connectorCount": "many"},
        {"connectorCount": 2.5},
        {"maxCurrent": None},
        {"maxCurrent": 10**9},
        {"minCurrent": -5},
        {"minCurrent": 32, "maxCurrent": 16},
        {"dipSwitchCurrentLimit": "big"},
        {"timezone": "Mars/Olympus_Mons"},
        {"timezone": "../../etc/passwd"},
        {"currency": "DOLLARS"},
        {"currency": "$$$"},
        {"displayName": "n" * 500},
    ],
)
async def test_settings_are_validated_before_anything_is_applied(station, patch):
    """A refused request used to leave its other fields (and sometimes the bad one) applied;
    connectorCount took any number (the same loop bomb as the charger-side one) and null made
    every later BootNotification fail."""
    client, headers, state = station
    before = json.dumps(state, sort_keys=True)
    body = {"displayName": "Renamed", "currency": "EUR", **patch}
    resp = await client.put(f"/local/stations/{SERIAL}/settings", json=body, headers=headers)
    assert resp.status == 400, await resp.text()
    assert json.dumps(state, sort_keys=True) == before  # not even the valid fields of a refused request


async def test_valid_settings_apply_together(station):
    client, headers, state = station
    body = {
        "displayName": "  Garage  ", "timezone": "America/Denver", "currency": "cad", "connectorCount": 2,
        "maxCurrent": 48, "minCurrent": 6, "dipSwitchCurrentLimit": 40,
    }
    resp = await client.put(f"/local/stations/{SERIAL}/settings", json=body, headers=headers)
    assert resp.status == 200, await resp.text()
    assert state["displayName"] == "Garage" and state["timezone"] == "America/Denver" and state["currency"] == "CAD"
    assert state["connectorCount"] == 2 and set(state["connectors"]) == {"1", "2"} and state["modelLocked"] is True
    assert (state["maxCurrent"], state["minCurrent"], state["dipSwitchCurrentLimit"]) == (48, 6, 40)
    resp = await client.put(f"/local/stations/{SERIAL}/settings", json={"dipSwitchCurrentLimit": None}, headers=headers)
    assert resp.status == 200 and state["dipSwitchCurrentLimit"] is None
    # Unknown or wrongly typed optional text is ignored, as before.
    resp = await client.put(f"/local/stations/{SERIAL}/settings", json={"displayName": 5, "x": 1}, headers=headers)
    assert resp.status == 200 and state["displayName"] == "Garage"


# --- schedules and rate zones ----------------------------------------------------------------------

GOOD_ZONE = {
    "name": "Night", "startHours": 23, "startMinutes": 0, "endHours": 7, "endMinutes": 0,
    "allDay": False, "days": [1, 2, 3, 4, 5], "connectorId": 0, "currentLimit": None,
}


@pytest.mark.parametrize(
    "bad",
    [
        {"startHours": "soon"},
        {"startHours": 25},
        {"endMinutes": 60},
        {"endHours": 24, "endMinutes": 1},
        {"startMinutes": -1},
        {"startHours": 1.5},
        {"startHours": True},
        {"startHours": [23]},
        {"days": 5},
        {"days": "weekdays"},
        {"days": [7]},
        {"days": [None]},
        {"days": [[1]]},
        {"connectorId": "left"},
        {"connectorId": 99},
        {"currentLimit": float("nan")},
        {"currentLimit": 10**6},
        {"currentLimit": -8},
        {"currentLimit": "fast"},
        {"priceKW": float("nan")},
        {"priceKW": float("inf")},
        {"priceKW": -1},
        {"priceKW": True},
        {"priceKW": "cheap"},
        {"allDay": "false"},
        {"scheduleEnabled": "yes"},
        {"holidays": "sometimes"},
        {"holidays": ["skip"]},
        {"name": 5},
        {"name": "n" * 500},
        {"_id": "has spaces"},
        {"_id": {"$ne": None}},
        {"_id": "x" * 65},
    ],
)
async def test_an_invalid_zone_is_refused_and_not_stored(station, bad, caplog):
    """An invalid zone used to be appended first and refused second: the reply said 400, the zone
    stayed, and every tick from then on raised while evaluating it."""
    client, headers, state = station
    caplog.set_level(logging.ERROR)
    for path in ("scheduleUpdate", "pricesByZoneUpdate"):
        body = json.dumps({"price": {**GOOD_ZONE, **bad}})  # json.dumps: lets NaN through, as a client could
        resp = await client.post(f"/client/stations/{SERIAL}/{path}", data=body, headers=headers)
        assert resp.status == 400, f"{bad} -> {resp.status} {await resp.text()}"
        assert state["pricesByZone"] == []
    await client.app["controller"]._tick_station(SERIAL)
    assert not caplog.records


async def test_zones_are_stored_normalised(station):
    client, headers, state = station
    sent = {
        **GOOD_ZONE, "name": "  Peak  ", "days": [5, 1, 1, 3.0, "2"], "startHours": "9", "endHours": 17.0,
        "priceKW": "0.30", "currentLimit": 0, "allDay": 0, "priceKWSummer": 0, "useSeason": False,
        "note": "kept", "nested": {"a": [1, 2]}, "huge": "h" * 5000, "nan": float("nan"), "deep": [[[[1]]] * 50] * 50,
    }
    resp = await client.post(f"/client/stations/{SERIAL}/pricesByZoneUpdate", data=json.dumps({"price": sent}),
                             headers=headers)
    assert resp.status == 200, await resp.text()
    data = strict_json(await resp.text())
    zone = state["pricesByZone"][0]
    assert zone == data["price"] and data["_id"] == zone["_id"] and zone_id(zone["_id"]) == zone["_id"]
    assert zone["name"] == "Peak" and zone["days"] == [1, 2, 3, 5]
    assert (zone["startHours"], zone["endHours"], zone["priceKW"]) == (9, 17, 0.3)
    assert zone["currentLimit"] is None and zone["allDay"] is False and zone["scheduleEnabled"] is False
    assert zone["note"] == "kept" and zone["nested"] == {"a": [1, 2]}  # small unknown fields are handed back
    assert "huge" not in zone and "nan" not in zone and "deep" not in zone  # large or non-JSON ones are not kept

    # An update merges into the zone and is validated as a whole; a refused update changes nothing.
    update = {"_id": zone["_id"], "scheduleEnabled": True, "endHours": 20}
    resp = await client.post(f"/client/stations/{SERIAL}/pricesByZoneUpdate", json={"price": update}, headers=headers)
    assert resp.status == 200 and state["pricesByZone"][0]["endHours"] == 20 and len(state["pricesByZone"]) == 1
    assert state["pricesByZone"][0]["scheduleEnabled"] is True and state["pricesByZone"][0]["name"] == "Peak"
    before = json.dumps(state["pricesByZone"])
    update = {"_id": zone["_id"], "name": "Renamed", "endHours": 99}
    resp = await client.post(f"/client/stations/{SERIAL}/pricesByZoneUpdate", json={"price": update}, headers=headers)
    assert resp.status == 400 and json.dumps(state["pricesByZone"]) == before


async def test_the_number_of_zones_is_bounded(station):
    client, headers, state = station
    for n in range(MAX_ZONES):
        resp = await client.post(f"/client/stations/{SERIAL}/scheduleUpdate",
                                 json={"price": {**GOOD_ZONE, "name": f"z{n}"}}, headers=headers)
        assert resp.status == 200
    resp = await client.post(f"/client/stations/{SERIAL}/scheduleUpdate", json={"price": GOOD_ZONE}, headers=headers)
    assert resp.status == 400 and len(state["pricesByZone"]) == MAX_ZONES
    # ...but the existing ones can still be changed.
    update = {"_id": state["pricesByZone"][0]["_id"], "name": "still editable"}
    resp = await client.post(f"/client/stations/{SERIAL}/scheduleUpdate", json={"price": update}, headers=headers)
    assert resp.status == 200 and state["pricesByZone"][0]["name"] == "still editable"


def test_normalize_zone_keeps_only_what_can_be_evaluated():
    assert normalize_zone({}) == {}
    assert normalize_zone({"days": None, "connectorId": None, "startHours": None}) == {
        "days": [], "connectorId": 0, "startHours": 0,
    }
    assert normalize_zone({"endHours": 24, "endMinutes": 0})["endHours"] == 24
    assert normalize_zone({"currentLimit": 16.0, "priceKW": 0})["currentLimit"] == 16
    assert normalize_zone({"connectorId": 3}, max_connector=4)["connectorId"] == 3
    with pytest.raises(ValueError):
        normalize_zone({"connectorId": 3}, max_connector=2)
    with pytest.raises(ValueError):
        normalize_zone("not a zone")
    many = normalize_zone({f"extra{n}": n for n in range(200)})
    assert len(many) == 32


# --- files on disk ----------------------------------------------------------------------------------


async def test_state_and_history_files_are_private(tmp_path, session):
    data = tmp_path / "data"
    data.mkdir()
    (data / "state.json").write_text("{}")
    (data / "state.json").chmod(0o644)  # as an older version left it
    (data / "state.tmp").write_text("leftover from a crash")
    (data / "state.tmp").chmod(0o644)
    async with TestServer(make_app(tmp_path)) as ts, TestClient(ts) as client:
        cp = await RawCharger.connect(client, session, SERIAL, auth=(SERIAL, "the-charger's-cloud-key"))
        await login(client)
        client.app["controller"].store.save()
        await cp.close()
        text = (data / "state.json").read_text()
        assert "the-charger's-cloud-key" in text  # which is exactly why the file must not be world-readable
        for name in ("state.json", "history.sqlite"):
            assert stat.S_IMODE((data / name).stat().st_mode) == 0o600, name
        assert not (data / "state.tmp").exists()


async def test_request_bodies_that_are_too_deep_are_refused(station):
    client, headers, _ = station
    resp = await client.put(f"/local/stations/{SERIAL}/settings", data=b"[" * 200_000,
                            headers={**headers, "Content-Type": "application/json"})
    assert resp.status == 400


async def test_unknown_station_and_wrong_session_are_unchanged(server):
    headers = await bearer(server)
    assert (await server.get("/client/stations/GRD-NOPE", headers=headers)).status == 404
    assert (await server.get("/client/stations", headers={"Authorization": "Bearer nope"})).status == 401
    assert (await server.get("/client/stations", headers={"Authorization": "Basic abc"})).status == 401


# --- a changed password signs everybody out ---------------------------------------------------------


async def test_changing_the_password_signs_out_existing_sessions(tmp_path):
    """Changing the password is what an owner does about a session that got into the wrong hands.
    The old sessions used to keep working, and could be refreshed for ever."""
    async with TestServer(make_app(tmp_path)) as ts, TestClient(ts) as client:
        tokens = await login(client)
    # Same credentials after a restart: still signed in.
    async with TestServer(make_app(tmp_path)) as ts, TestClient(ts) as client:
        headers = {"Authorization": f"Bearer {tokens['token']}"}
        assert (await client.get("/client/stations", headers=headers)).status == 200
    # A new password: the old session is gone, token and refresh token alike.
    async with TestServer(make_app(tmp_path, api_password="a different password")) as ts, TestClient(ts) as client:
        assert (await client.get("/client/stations", headers=headers)).status == 401
        resp = await client.post("/client/auth/refresh-token", json={"refreshToken": tokens["refreshToken"]})
        assert resp.status == 401
        renewed = await login(client, password="a different password")
    # A new email does the same.
    app = make_app(tmp_path, api_password="a different password", api_email="someone@else")
    async with TestServer(app) as ts, TestClient(ts) as client:
        headers = {"Authorization": f"Bearer {renewed['token']}"}
        assert (await client.get("/client/stations", headers=headers)).status == 401
    state = json.loads((tmp_path / "data" / "state.json").read_text())
    assert PASSWORD not in json.dumps(state) and "a different password" not in json.dumps(state)
    assert set(state["credentials"]) == {"salt", "mark"}


# --- requests from web pages -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "origin,host,allowed",
    [
        ("http://192.168.1.5:9000", "192.168.1.5:9000", True),  # the page itself, by address
        ("http://192.168.1.5:9000", "127.0.0.1:9000", True),  # the same through a proxy that rewrites Host
        ("http://[fd00::5]:9000", "[fd00::5]:9000", True),
        ("http://100.64.3.2:9000", "100.64.3.2:9000", True),  # carrier-grade NAT range (Tailscale addresses)
        ("http://localhost:9000", "localhost:9000", True),
        ("http://nas:9000", "nas:9000", True),  # a single-label name
        ("http://NAS.local:9000", "nas.local:9000", True),
        ("https://truenas.home.arpa", "truenas.home.arpa", True),
        ("http://8.8.8.8:9000", "8.8.8.8:9000", True),  # a public address, but it is our own page's
        ("http://8.8.8.8:9000", "192.168.1.5:9000", False),  # ...and here it is someone else's
        ("http://attacker.example:9000", "attacker.example:9000", False),  # DNS rebinding: same origin, public name
        ("https://evil.example", "192.168.1.5:9000", False),  # another site posting to us
        ("http://ocpp.unitedchargers.com.evil.example", "192.168.1.5:9000", False),
        ("http://local", "x", True),
        ("http://notlocal.com", "notlocal.com", False),
        ("null", "192.168.1.5:9000", False),
        ("file://", "192.168.1.5:9000", False),
        ("chrome-extension://abcdef", "192.168.1.5:9000", False),
        ("", "192.168.1.5:9000", False),
        ("http://[bad", "192.168.1.5:9000", False),
    ],
)
def test_which_web_origins_may_use_the_api(origin, host, allowed):
    assert api_module.origin_allowed(origin, host, ()) is allowed


def test_allowed_hosts_setting(monkeypatch):
    assert Settings().allowed_hosts == ()
    monkeypatch.setenv("GRIZZLE_ALLOWED_HOSTS", "Grizzle.Example.com, .ts.net")
    hosts = Settings().allowed_hosts
    assert hosts == ("grizzle.example.com", ".ts.net")
    assert api_module.origin_allowed("https://grizzle.example.com", "127.0.0.1:9000", hosts)
    assert api_module.origin_allowed("https://nas.tail1234.ts.net", "x", hosts)
    assert not api_module.origin_allowed("https://other.example.com", "x", hosts)
    assert not api_module.origin_allowed("https://evilts.net", "x", hosts)
    assert api_module.origin_allowed("https://anything.example", "x", Settings(allowed_hosts="*").allowed_hosts)


async def test_a_page_from_a_public_name_cannot_use_the_api(server, caplog):
    """DNS rebinding: a web site re-points its own name at this server, and the owner's browser then
    treats the site's script as the API's own origin. Such a page must not even get to try a
    password (nor may another site's page burn the owner's sign-in attempts)."""
    caplog.set_level(logging.WARNING)
    body = {"emailOrPhone": EMAIL, "password": PASSWORD}
    for origin in ("http://attacker.example:9000", "https://evil.example", "null"):
        resp = await server.post("/client/auth/login", json=body, headers={"Origin": origin})
        assert resp.status == 403, origin
        assert "GRIZZLE_ALLOWED_HOSTS" in (await resp.json())["message"]
    for _ in range(api_module.LOGIN_MAX_FAILURES + 5):  # refused before it counts as a failed sign-in
        bad = {"emailOrPhone": EMAIL, "password": "guess"}
        resp = await server.post("/client/auth/login", json=bad, headers={"Origin": "https://evil.example"})
        assert resp.status == 403
    token = (await login(server))["token"]  # the owner is not locked out by any of that
    headers = {"Authorization": f"Bearer {token}", "Origin": "http://attacker.example:9000"}
    assert (await server.post("/client/auth/logout", headers=headers)).status == 403
    assert any("attacker.example" in r.getMessage() for r in caplog.records)

    # The server's own page (a LAN address or name) and non-browser clients are unaffected.
    own = {"Authorization": f"Bearer {token}", "Origin": f"http://{server.host}:{server.port}"}
    assert (await server.get("/client/stations", headers=own)).status == 200
    resp = await server.post("/client/auth/login", json=body, headers={"Origin": "http://nas.local:9000"})
    assert resp.status == 200
    assert (await server.post("/client/auth/login", json=body)).status == 200
    # Pages (which need no token) are still served to anyone; only the API is guarded.
    assert (await server.get("/", headers={"Origin": "https://evil.example"})).status == 200


async def test_a_listed_public_name_may_use_the_api(tmp_path):
    async with TestServer(make_app(tmp_path, allowed_hosts="grizzle.example.com")) as ts, TestClient(ts) as client:
        body = {"emailOrPhone": EMAIL, "password": PASSWORD}
        resp = await client.post("/client/auth/login", json=body, headers={"Origin": "https://grizzle.example.com"})
        assert resp.status == 200
        resp = await client.post("/client/auth/login", json=body, headers={"Origin": "https://other.example.com"})
        assert resp.status == 403


@pytest.mark.parametrize(
    "content_type", ["application/json; charset=no-such-codec", "application/json; charset=", "text/plain"]
)
async def test_odd_content_types_are_not_server_errors(server, content_type):
    body = json.dumps({"emailOrPhone": EMAIL, "password": "wrong"}).encode()
    resp = await server.post("/client/auth/login", data=body, headers={"Content-Type": content_type})
    assert resp.status in (400, 401), resp.status


# --- a timezone the system doesn't know -------------------------------------------------------------


def test_an_unknown_timezone_is_reported_not_silently_utc(tmp_path, caplog):
    """TZ=US/Mountain on an image without the legacy zone names, or a typo: schedules were quietly
    evaluated in UTC, hours away from the owner's clock."""
    from grizzle_local.controller import Controller
    from grizzle_local.store import Store

    settings = Settings(data_dir=tmp_path / "data", timezone="Mars/Olympus_Mons", api_password="a long passphrase")
    assert any("Mars/Olympus_Mons" in warning and "UTC" in warning for warning in settings.security_warnings())
    assert not Settings(timezone="America/Denver", api_password="a long passphrase").security_warnings()
    # An old alias that the base image's zone database no longer carries: the tzdata dependency does.
    assert not Settings(timezone="US/Mountain", api_password="a long passphrase").security_warnings()

    caplog.set_level(logging.WARNING)
    controller = Controller(settings, Store(settings.data_dir))
    station = controller._ensure_station(SERIAL)
    for _ in range(5):
        assert str(controller.tz(station)) == "UTC"
    reports = [r for r in caplog.records if "Mars/Olympus_Mons" in r.getMessage()]
    assert len(reports) == 1  # said once, not on every tick
