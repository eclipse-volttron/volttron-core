"""Core.stop() returns even when the agentstop notice cannot be sent (volttron-core#360).

On a zmq DEALER socket whose router is gone the send waits for the socket to become writable, which never
happens; stop() used to wait with it, so an agent that outlived its platform could not be stopped.
"""
import time
from types import SimpleNamespace

import gevent

from volttron.client.vip.agent.core import BasicCore, Core


class _BlockingConnection:
    connected = True

    def __init__(self):
        self.sent = []

    def send_vip(self, peer, subsystem, args=None, copy=False):
        gevent.sleep(3600)    # a send to a router that is not there
        self.sent.append(subsystem)


class _Connection(_BlockingConnection):
    def send_vip(self, peer, subsystem, args=None, copy=False):
        self.sent.append(subsystem)


class _Core(Core):
    def loop(self, running_event):    # abstract in Core; never run here
        raise NotImplementedError


def _core(connection, monkeypatch):
    stopped = []
    monkeypatch.setattr(BasicCore, "stop", lambda self, timeout=None: stopped.append(timeout))
    core = _Core.__new__(_Core)    # stop() only needs the connection and the identity
    core._connection = connection
    core.identity = "test.agent"
    core.stop_notify_timeout = 0.2
    return core, stopped


def test_stop_returns_when_the_notice_cannot_be_sent(monkeypatch):
    core, stopped = _core(_BlockingConnection(), monkeypatch)
    started = time.monotonic()
    with gevent.Timeout(5):
        core.stop(timeout=1)
    assert time.monotonic() - started < 2
    assert stopped == [1]


def test_stop_sends_the_notice_when_it_can(monkeypatch):
    connection = _Connection()
    core, stopped = _core(connection, monkeypatch)
    core.stop()
    assert connection.sent == ["agentstop"] and stopped == [None]


def test_stop_skips_the_notice_when_the_link_is_down(monkeypatch):
    connection = _Connection()
    connection.connected = False
    core, stopped = _core(connection, monkeypatch)
    core.stop()
    assert connection.sent == [] and stopped == [None]


def test_platform_shutdown_skips_the_notice(monkeypatch):
    connection = _Connection()
    core, stopped = _core(connection, monkeypatch)
    core.stop(platform_shutdown=True)
    assert connection.sent == [] and stopped == [None]
