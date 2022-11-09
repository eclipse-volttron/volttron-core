from __future__ import annotations
from dataclasses import dataclass
from typing import Type

from volttron.types.credentials import CredentialsGenerator
#from volttron.types import BaseConnection
from volttron.types.agent_factory import AgentFactory
from volttron.utils import get_class, get_subclasses
from volttron.utils.dynamic_helper import get_all_subclasses


@dataclass
class Factories:
    namespace: str

    def agent_factory(self) -> AgentFactory:
        agent_factory_class = get_subclasses(self.namespace, AgentFactory, False)[0]
        return agent_factory_class()

    def agent_core(self):
        from volttron.client.vip.agent.core import Core
        core_class = get_subclasses(self.namespace, Core, False)[0]
        return core_class()

    def credential_generator(self) -> Type[CredentialsGenerator]:
        cls = get_all_subclasses(CredentialsGenerator)[0]
        cls = get_subclasses(self.namespace, CredentialsGenerator)[0]
        return cls



    # def connection(self, **kwargs) -> BaseConnection:
    #     core_class = get_subclasses(self.namespace, BaseConnection, False)[0]
    #     return core_class(**kwargs)

if __name__ == '__main__':
    f = Factories("volttron.messagebus.zmq")
    assert isinstance(f.agent_factory(), AgentFactory)
