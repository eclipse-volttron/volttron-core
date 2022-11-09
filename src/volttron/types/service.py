import logging
from typing import Dict, Any

import gevent
from gevent import Greenlet

from volttron.client.vip.agent import Agent
from volttron.types.credentials import Credentials
from volttron.types.errors import MessageBusConnectionError


_log = logging.getLogger(__name__)


class ServiceInterface(Agent):

    # def __init__(self, **kwargs):
    #     super().__init__(**kwargs)
    #     #self.server_config = server_config

    @classmethod
    def get_kwargs_defaults(cls) -> Dict[str, Any]:
        """
        Class method that allows the specific class to have the ability to specify
        what service arguments are available as defaults.
        """
        return {}

    def set_credentials(self, credential: Credentials):
        self._credentials = credential