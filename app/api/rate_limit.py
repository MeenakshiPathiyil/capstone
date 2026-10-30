"""Per-client limits on the requests that start expensive work.

Each bucket (analyses, reports, scenarios) allows `count` requests per client
in any sliding `window` of seconds. A route passes `admission(request, bucket)`
to the service, which calls it just before the work starts, so a request that
is refused for another reason (busy, invalid) or answered from what is saved
costs nothing. Past the limit the call raises JobError(429) with Retry-After.

State is in memory, which is enough for the single instance this is deployed
as. Everything runs on the event loop, so nothing here needs a lock. A client
is idle once its newest request has left the window, and idle clients are
dropped as the limiter goes, with a hard cap on how many it tracks at all.
"""

import ipaddress
import math
import time
from collections import OrderedDict, deque
from typing import Callable

from fastapi import Request

from app.api.config import Settings
from app.api.worker import JobError


# What each bucket counts, for the 429 message.
NOUNS = {
    "analyses": "analyses",
    "reports": "PDF reports",
    "scenarios": "scenario generations"
}

# Most clients tracked at once. Past it the least recently seen is forgotten.
MAX_CLIENTS = 10_000

# Seconds between sweeps for idle clients.
SWEEP_INTERVAL_S = 60.0

# IPv6 clients are keyed by their /64, which one host usually holds whole.
IPV6_PREFIX = 64


def per_window(window_s):
    """600 -> "10 minutes", 3600 -> "hour", 60 -> "minute"."""

    for unit_s, unit in ((3600, "hour"), (60, "minute"), (1, "second")):

        if window_s % unit_s == 0:
            count = window_s // unit_s
            return unit if count == 1 else "%d %ss" % (count, unit)


def client_key(address):
    """The address a client is counted under: itself, or its /64 for IPv6."""

    try:
        ip = ipaddress.ip_address(address)

    except ValueError:
        return address

    if ip.version == 6:
        return str(ipaddress.ip_network((ip, IPV6_PREFIX), strict=False))

    return str(ip)


def client_address(request: Request, trusted_proxy_hops):
    """The client's address, read through `trusted_proxy_hops` proxies.

    Each trusted proxy appends the address it received the request from to
    X-Forwarded-For, so the Nth entry from the right is the one the outermost
    trusted proxy saw. Anything left of it came from the client. Without a
    long enough header the connection's own address is used.
    """

    connection = request.client.host if request.client else "unknown"

    if trusted_proxy_hops <= 0:
        return connection

    entries = [
        entry.strip()
        for header in request.headers.getlist("x-forwarded-for")
        for entry in header.split(",")
        if entry.strip()
    ]

    if len(entries) < trusted_proxy_hops:
        return connection

    return entries[-trusted_proxy_hops]


class RateLimiter:
    """Sliding-window counts per (bucket, client), bounded in memory."""

    def __init__(self, settings: Settings, clock=time.monotonic):
        self.enabled = settings.rate_limits_enabled
        self.trusted_proxy_hops = settings.trusted_proxy_hops
        self.limits = {
            "analyses": settings.rate_limit_analyses,
            "reports": settings.rate_limit_reports,
            "scenarios": settings.rate_limit_scenarios
        }
        self.clock = clock

        self._hits: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()
        self._swept_at = clock()

    def charge(self, bucket, request: Request):
        """Count one `bucket` request for the request's client, or raise 429."""

        if not self.enabled:
            return

        count, window_s = self.limits[bucket]
        now = self.clock()

        self._sweep(now)

        key = (bucket, client_key(client_address(request, self.trusted_proxy_hops)))
        hits = self._hits.get(key)

        if hits is None:

            if len(self._hits) >= MAX_CLIENTS:
                self._hits.popitem(last=False)

            hits = self._hits[key] = deque()

        self._hits.move_to_end(key)

        while hits and hits[0] <= now - window_s:
            hits.popleft()

        if len(hits) >= count:
            retry_after_s = max(math.ceil(hits[0] + window_s - now), 1)

            raise JobError(
                429,
                "Too many %s from this address: the limit is %d per %s."
                % (NOUNS[bucket], count, per_window(window_s)),
                {"Retry-After": str(retry_after_s)}
            )

        hits.append(now)

    def _sweep(self, now):
        """Drop the clients whose newest request has left its bucket's window."""

        if now - self._swept_at < SWEEP_INTERVAL_S:
            return

        self._swept_at = now

        for key in [
            key for key, hits in self._hits.items()
            if not hits or hits[-1] <= now - self.limits[key[0]][1]
        ]:
            del self._hits[key]


def admission(request: Request, bucket) -> Callable[[], None]:
    """What a service calls just before it starts `bucket` work for this request."""

    limiter = request.app.state.limiter

    return lambda: limiter.charge(bucket, request)
