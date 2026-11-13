"""The container's health check: ``python -m grizzle_local.healthcheck`` exits 0 if the server answers.

It asks wherever the server was told to listen (GRIZZLE_HOST / GRIZZLE_PORT), not a fixed
127.0.0.1:9000, so changing either doesn't leave a healthy container marked unhealthy for ever.
"""

from __future__ import annotations

import sys
import urllib.request

from .config import Settings
from .tls import upstream_host


def url(settings: Settings) -> str:
    host = upstream_host(settings.host)
    return f"http://{f'[{host}]' if ':' in host else host}:{settings.port}/health"


def main() -> int:
    try:
        # No proxy: this is a request to ourselves, whatever http_proxy says.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url(Settings()), timeout=4) as response:
            return 0 if response.status == 200 else 1
    except Exception as err:  # noqa: BLE001 - any failure means "not healthy"
        print(f"health check failed: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
