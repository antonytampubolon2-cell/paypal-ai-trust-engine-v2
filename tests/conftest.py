"""Global offline-test guard: no test may open a real network connection."""
import socket

import pytest
import requests


@pytest.fixture(autouse=True)
def forbid_real_network(monkeypatch):
    def blocked_network(*_args, **_kwargs):
        raise AssertionError("real network access is prohibited in the offline test suite")

    monkeypatch.setattr(requests.sessions.Session, "request", blocked_network)
    monkeypatch.setattr(socket, "create_connection", blocked_network)
    monkeypatch.setattr(socket.socket, "connect", blocked_network)
