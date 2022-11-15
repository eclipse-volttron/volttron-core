from typing import Dict, Any

import gevent
from gevent import Greenlet

from volttron.client.vip.agent import Agent
from volttron.types.server_config import ServerConfig


class ServiceInterface(Agent):

    def __init__(self, server_config: ServerConfig = None, **kwargs):
        self._server_config = server_config
        super().__init__(**kwargs)

    @classmethod
    def get_kwargs_defaults(cls) -> Dict[str, Any]:
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
