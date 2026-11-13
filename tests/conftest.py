"""Suite-wide test settings."""

import pytest

from grizzle_local import api


@pytest.fixture(autouse=True)
def _fast_credential_mark(monkeypatch):
    """The slow hash that marks which credentials sessions belong to is deliberately expensive
    (a tenth of a second); hundreds of tests sign in. Its cost is not what they are testing."""
    monkeypatch.setattr(api, "CREDENTIAL_ROUNDS", 1000)


@pytest.fixture(autouse=True)
def _no_proxy_for_loopback(monkeypatch):
    """Several tests talk to servers they start on 127.0.0.1 through urllib, which honours
    http_proxy. Wherever the suite runs, those requests must go to the test's own server."""
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "127.0.0.1,localhost,::1")
