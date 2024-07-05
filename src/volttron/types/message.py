from dataclasses import dataclass, field
from typing import Any

from dataclass_wizard import JSONSerializable


class Message(object):
    """Message object returned form Socket.recv_vip_object()."""

    def __init__(self, **kwargs):
        self.__dict__ = kwargs

    def __repr__(self):
        attrs = ", ".join("%r: %r" % (
            name,
            [x for x in value] if isinstance(value, (list, tuple)) else value,
        ) for name, value in self.__dict__.items())
        return "%s(**{%s})" % (self.__class__.__name__, attrs)
