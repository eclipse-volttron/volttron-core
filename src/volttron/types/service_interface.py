from typing import Any

from gevent import Greenlet

from volttron.client.vip.agent import Agent
from volttron.types import Service
from volttron.types.message import Message
from volttron.types.server_config import ServerConfig


class ServiceInterface(Agent):

    def __init__(self, server_config: ServerConfig = None, **kwargs):
        self._server_config = server_config
        super().__init__(**kwargs)

    @classmethod
    def get_kwargs_defaults(cls) -> dict[str, Any]:
        """
        Class method that allows the specific class to have the ability to specify
        what service arguments are available as defaults.
        """
        return {}

    def spawn_in_greenlet(self) -> Greenlet:
        """
        Start the execution of a volttron agent.
        """
        event = gevent.event.Event()
        task = gevent.spawn(self.core.run, event)
        event.wait()
        del event
        return task
