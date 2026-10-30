"""A worker entrypoint that never answers, for the timeout tests.

Module level so a spawned child can import it by name, like the real one.
"""

import time


def stall(connection, kind, request):
    time.sleep(3600)


def crash(connection, kind, request):
    raise SystemExit(3)


def big_reply(connection, kind, request):
    connection.send_bytes(b"x" * 100_000)
