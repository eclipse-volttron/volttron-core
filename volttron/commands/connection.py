import gevent

from volttron.utils import ClientContext as cc
from volttron.client.known_identities import CONTROL_CONNECTION
from volttron.client.vip.agent import Agent as BaseAgent

class ControlConnection(object):
    def __init__(self, address, peer="control"):
        self.address = address
        self.peer = peer
        message_bus = cc.get_messagebus()
        self._server = BaseAgent(
            address=self.address,
            enable_store=False,
            identity=CONTROL_CONNECTION,
            message_bus=message_bus,
            enable_channel=True,
        )
        self._greenlet = None

    @property
    def server(self):
        if self._greenlet is None:
            event = gevent.event.Event()
            self._greenlet = gevent.spawn(self._server.core.run, event)
            event.wait()
        return self._server

    def call(self, method, *args, **kwargs):
        return self.server.vip.rpc.call(self.peer, method, *args, **kwargs).get(timeout=20)

    def call_no_get(self, method, *args, **kwargs):
        return self.server.vip.rpc.call(self.peer, method, *args, **kwargs)

    def notify(self, method, *args, **kwargs):
        return self.server.vip.rpc.notify(self.peer, method, *args, **kwargs)

    def kill(self, *args, **kwargs):
        if self._greenlet is not None:
            self._greenlet.kill(*args, **kwargs)
