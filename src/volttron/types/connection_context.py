from dataclasses import dataclass

from volttron.types.message_bus import ConnectionParameters


class BaseConnection:
    """
    A BaseConnection is a hook for subclass objects to be found dynamically from external
    sources.
    """
    pass


class ConnectionContext:
    """
    Base class for any connection to a message bus.
    """
    def __init__(self, identity: str, params: ConnectionParameters):
        """
        Constructor for creating a ConnectionContext object.

        :param identity:
            An identity to be used to connect to a MessageBus
        :param params:
            An object representing the ConnectionParameters required to connect to a MessageBus
        """
        self._identity = identity
        self._connection_parameters = params

    @property
    def identity(self):
        return self._identity

    @property
    def connection_parameters(self):
        return self._connection_parameters


if __name__ == '__main__':

    ctx = ConnectionContext("foo", None)
    assert ctx.identity == "foo"

    try:
        ctx2 = ConnectionContext("bar", None)
    except ValueError:
        pass