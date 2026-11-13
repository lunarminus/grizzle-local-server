#!/usr/bin/env python3
"""A pretend Grizzl-E that speaks OCPP 1.6-J the way the real one does.

Used by the tests and handy for trying the server without a charger:

    python tools/fake_charger.py ws://localhost:9000/ocpp1.6/GRD-FAKE0001 --plug-in 5

It boots, reports its connectors, plugs a car in after ``--plug-in`` seconds and
then waits for RemoteStartTransaction like the real thing. It also reproduces the
firmware's malformed GetConfiguration reply so the server's tolerance is exercised.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import random
import uuid
from datetime import UTC, datetime
from typing import Any

import aiohttp

_LOGGER = logging.getLogger("fake_charger")


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class FakeCharger:
    def __init__(
        self,
        url: str,
        serial: str,
        connectors: int = 2,
        meter_interval: float = 5.0,
        malformed_config: bool = True,
        auth_key: str = "secret",
        insecure: bool = False,
    ) -> None:
        self.url = url
        self.insecure = insecure
        self.serial = serial
        self.connector_count = connectors
        self.meter_interval = meter_interval
        self.malformed_config = malformed_config
        self.auth_key = auth_key
        self.status = {cid: "Available" for cid in range(1, connectors + 1)}
        self.transactions: dict[int, dict[str, Any]] = {}  # connector -> {id, meter}
        self.energy = {cid: 500_000 + cid * 1000 for cid in range(1, connectors + 1)}  # Wh register
        self.limit_a: int | None = None
        self.config = {"HeartbeatInterval": "3600", "MeterValueSampleInterval": "60"}
        self.received: list[tuple[str, dict[str, Any]]] = []  # server -> charger calls, for assertions
        self.ws: aiohttp.ClientWebSocketResponse | None = None
        self._pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self.booted = asyncio.Event()
        self.reset_requested = asyncio.Event()
        self._tasks: list[asyncio.Task[Any]] = []

    # --- transport -----------------------------------------------------------

    async def connect(self, session: aiohttp.ClientSession) -> None:
        self.ws = await session.ws_connect(
            self.url,
            protocols=("ocpp1.6",),
            heartbeat=30,
            headers={"Authorization": aiohttp.BasicAuth(self.serial, self.auth_key).encode()},
            ssl=False if self.insecure else True,
        )
        _LOGGER.info("connected to %s (subprotocol %s)", self.url, self.ws.protocol)

    async def call(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        assert self.ws is not None
        uid = uuid.uuid4().hex[:8]
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[uid] = fut
        await self.ws.send_str(json.dumps([2, uid, action, payload]))
        try:
            return await asyncio.wait_for(fut, 30)
        finally:
            self._pending.pop(uid, None)

    async def run(self) -> None:
        assert self.ws is not None
        self._tasks = [asyncio.create_task(self._boot_sequence()), asyncio.create_task(self._meter_loop())]
        try:
            async for msg in self.ws:
                if msg.type != aiohttp.WSMsgType.TEXT:
                    continue
                frame = json.loads(msg.data)
                if frame[0] == 3:
                    fut = self._pending.get(frame[1])
                    if fut and not fut.done():
                        fut.set_result(frame[2])
                elif frame[0] == 4:
                    fut = self._pending.get(frame[1])
                    if fut and not fut.done():
                        fut.set_exception(RuntimeError(f"{frame[2]}: {frame[3]}"))
                elif frame[0] == 2:
                    await self._handle_call(frame[1], frame[2], frame[3])
        finally:
            for task in self._tasks:
                task.cancel()

    async def close(self) -> None:
        if self.ws:
            await self.ws.close()

    # --- charger -> server ----------------------------------------------------

    async def _boot_sequence(self) -> None:
        result = await self.call(
            "BootNotification",
            {
                "chargePointVendor": "UnitedChargers",
                "chargePointModel": "GRD 40A 2025",
                "chargePointSerialNumber": self.serial,
                "firmwareVersion": "UDGRW070L-04.03.2",
                "meterType": "0",
            },
        )
        _LOGGER.info("BootNotification -> %s", result)
        for cid in range(1, self.connector_count + 1):
            await self.send_status(cid, self.status[cid])
        self.booted.set()
        interval = int(result.get("interval") or 300)
        while True:
            await asyncio.sleep(interval)
            await self.call("Heartbeat", {})

    async def send_status(self, cid: int, status: str) -> None:
        self.status[cid] = status
        await self.call(
            "StatusNotification",
            {
                "connectorId": cid,
                "status": status,
                "errorCode": "NoError",
                "timestamp": now_iso(),
            },
        )

    async def plug_in(self, cid: int) -> None:
        await self.send_status(cid, "Preparing")

    async def unplug(self, cid: int) -> None:
        if cid in self.transactions:
            await self._stop_transaction(cid, "EVDisconnected")
        await self.send_status(cid, "Available")

    async def _start_transaction(self, cid: int, id_tag: str) -> None:
        result = await self.call(
            "StartTransaction",
            {
                "connectorId": cid,
                "idTag": id_tag,
                "meterStart": self.energy[cid],
                "timestamp": now_iso(),
            },
        )
        self.transactions[cid] = {"id": result["transactionId"], "idTag": id_tag}
        await self.send_status(cid, "Charging")

    async def _stop_transaction(self, cid: int, reason: str) -> None:
        tx = self.transactions.pop(cid)
        await self.send_status(cid, "Finishing")
        await self.call(
            "StopTransaction",
            {
                "transactionId": tx["id"],
                "idTag": tx["idTag"],
                "meterStop": self.energy[cid],
                "timestamp": now_iso(),
                "reason": reason,
            },
        )

    async def _meter_loop(self) -> None:
        while True:
            await asyncio.sleep(self.meter_interval)
            for cid, tx in list(self.transactions.items()):
                if self.status[cid] != "Charging":
                    continue
                amps = min(self.limit_a or 32, 32)
                watts = amps * 240
                self.energy[cid] += int(watts * self.meter_interval / 3600)
                await self.call(
                    "MeterValues",
                    {
                        "connectorId": cid,
                        "transactionId": tx["id"],
                        "meterValue": [
                            {
                                "timestamp": now_iso(),
                                "sampledValue": [
                                    {
                                        "value": str(self.energy[cid]),
                                        "measurand": "Energy.Active.Import.Register",
                                        "unit": "Wh",
                                    },
                                    {"value": str(watts), "measurand": "Power.Active.Import", "unit": "W"},
                                    {"value": str(amps), "measurand": "Current.Import", "unit": "A"},
                                    {"value": str(240 + random.randint(-3, 3)), "measurand": "Voltage", "unit": "V"},
                                    {"value": "21", "measurand": "Temperature", "unit": "Celsius"},
                                ],
                            }
                        ],
                    },
                )

    # --- server -> charger ----------------------------------------------------

    async def _handle_call(self, uid: str, action: str, payload: dict[str, Any]) -> None:
        assert self.ws is not None
        self.received.append((action, payload))
        _LOGGER.info("<- %s %s", action, payload)
        if action == "GetConfiguration" and self.malformed_config and not payload.get("key"):
            # The real firmware's bug, verbatim: a missing '[' and the socket stays open.
            await self.ws.send_str(f'[3,"{uid}",{{"configurationKey":],"unknownKey":["MeterValuesSampledData"]}}]')
            return
        reply: dict[str, Any] = {}
        if action == "RemoteStartTransaction":
            cid = int(payload.get("connectorId") or 1)
            if self.status.get(cid) in ("Preparing", "SuspendedEVSE") and cid not in self.transactions:
                reply = {"status": "Accepted"}
                asyncio.create_task(self._start_transaction(cid, payload.get("idTag", "")))
            else:
                reply = {"status": "Rejected"}
        elif action == "RemoteStopTransaction":
            cid = next((c for c, tx in self.transactions.items() if tx["id"] == payload.get("transactionId")), None)
            if cid is None:
                reply = {"status": "Rejected"}
            else:
                reply = {"status": "Accepted"}

                async def stop_then_wait(cid: int = cid) -> None:
                    await self._stop_transaction(cid, "Remote")
                    await self.send_status(cid, "Preparing")  # car is still plugged in

                asyncio.create_task(stop_then_wait())
        elif action == "SetChargingProfile":
            period = payload["csChargingProfiles"]["chargingSchedule"]["chargingSchedulePeriod"][0]
            self.limit_a = int(period["limit"])
            reply = {"status": "Accepted"}
        elif action == "ChangeConfiguration":
            self.config[payload["key"]] = payload["value"]
            reply = {"status": "Accepted"}
        elif action == "GetConfiguration":
            reply = {
                "configurationKey": [{"key": k, "readonly": False, "value": v} for k, v in self.config.items()],
                "unknownKey": [],
            }
        elif action == "TriggerMessage":
            reply = {"status": "Accepted"}
            if payload.get("requestedMessage") == "StatusNotification":
                cid = int(payload.get("connectorId") or 1)
                if cid in self.status:
                    asyncio.create_task(self.send_status(cid, self.status[cid]))
                else:  # a connector this charger doesn't have (the server may assume a Duo's two)
                    reply = {"status": "Rejected"}
        elif action == "Reset":
            reply = {"status": "Accepted"}
            self.reset_requested.set()
        else:
            await self.ws.send_str(json.dumps([4, uid, "NotImplemented", f"{action} not supported", {}]))
            return
        await self.ws.send_str(json.dumps([3, uid, reply]))


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", help="e.g. ws://localhost:9000/ocpp1.6/GRD-FAKE0001")
    parser.add_argument("--connectors", type=int, default=2)
    parser.add_argument(
        "--plug-in", type=float, default=0, metavar="SECONDS", help="plug a car into connector 1 after N seconds"
    )
    parser.add_argument("--meter-interval", type=float, default=5)
    parser.add_argument("--insecure", action="store_true", help="accept a self-signed certificate on wss:// URLs")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    serial = args.url.rstrip("/").rsplit("/", 1)[-1]
    charger = FakeCharger(args.url, serial, args.connectors, args.meter_interval, insecure=args.insecure)
    async with aiohttp.ClientSession() as session:
        await charger.connect(session)
        runner = asyncio.create_task(charger.run())
        await charger.booted.wait()
        if args.plug_in:
            await asyncio.sleep(args.plug_in)
            await charger.plug_in(1)
        await runner


if __name__ == "__main__":
    asyncio.run(main())
