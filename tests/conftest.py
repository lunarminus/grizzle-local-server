"""Suite-wide test settings."""

import pytest

from grizzle_local import api


@pytest.fixture(autouse=True)
def _fast_credential_mark(monkeypatch):
    """The slow hash that marks which credentials sessions belong to is deliberately expensive
    (a tenth of a second); hundreds of tests sign in. Its cost is not what they are testing."""
    monkeypatch.setattr(api, "CREDENTIAL_ROUNDS", 1000)
