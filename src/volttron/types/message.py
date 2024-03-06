from dataclasses import field, dataclass
from typing import Any
from dataclass_wizard import JSONSerializable


@dataclass(frozen=True)
class Message(JSONSerializable):
    recipient: str
    sender: str = ''
    peer: str = ''
    subsystem: str = ''
    id: str = ''
    user_id: str = ''
    signature: str = 'VIP1'
    args: list[any] = field(default_factory=list)
