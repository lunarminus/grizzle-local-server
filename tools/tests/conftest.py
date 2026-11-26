"""Shared fixtures for the tests of the Python tools and the shell scripts.

The server itself is Rust and has its own tests (`cargo test`). Where a tool has to be tried
against it, these tests start the real binary.
"""

import json
import shutil
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "correct horse battery"


@pytest.fixture(autouse=True)
def _no_proxy_for_loopback(monkeypatch):
    """Several tests talk to servers they start on 127.0.0.1 through urllib, which honours
    http_proxy. Wherever the suite runs, those requests must go to the test's own server."""
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "127.0.0.1,localhost,::1")


@pytest.fixture
def certs(tmp_path):
    """A self-signed certificate and key from scripts/make-cert.sh."""
    subprocess.run([str(ROOT / "scripts/make-cert.sh"), str(tmp_path)], check=True, capture_output=True)
    return tmp_path / "fullchain.pem", tmp_path / "privkey.pem"


def wait_for(predicate, timeout: float = 10.0, step: float = 0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(step)
    raise AssertionError("condition not met in time")


class RustServer:
    """A running server: where it listens, and its REST API as a signed-in client."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.token: str | None = None

    def request(self, path: str, body: dict | None = None):
        """GET, or POST with a JSON body; the JSON that comes back."""
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, headers=headers)
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    def answers(self) -> bool:
        try:
            return self.request("/health")["status"] == "ok"
        except OSError:
            return False


@pytest.fixture(scope="session")
def server_binary() -> Path:
    """The Rust server, built once per run (cargo does nothing when it is up to date)."""
    binary = ROOT / "target" / "debug" / "grizzle-local"
    if shutil.which("cargo"):
        subprocess.run(["cargo", "build", "--quiet"], cwd=ROOT, check=True)
    if not binary.is_file():
        pytest.skip(f"the server is not built ({binary} is missing and there is no cargo here): run `cargo build`")
    return binary


@pytest.fixture
def rust_server(server_binary, tmp_path):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = {"GRIZZLE_DATA_DIR": str(tmp_path / "data"), "GRIZZLE_HOST": "127.0.0.1", "GRIZZLE_PORT": str(port),
           "GRIZZLE_TLS_PORT": "0", "GRIZZLE_API_PASSWORD": PASSWORD}
    process = subprocess.Popen([str(server_binary)], env=env)
    try:
        server = RustServer(port)
        wait_for(server.answers)
        login = {"emailOrPhone": "admin@local", "password": PASSWORD}
        server.token = server.request("/client/auth/login", login)["token"]
        yield server
    finally:
        process.terminate()
        process.wait(10)
