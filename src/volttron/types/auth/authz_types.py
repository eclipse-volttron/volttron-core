from dataclasses import dataclass
from typing import Optional

from dataclass_wizard import JSONSerializable


@dataclass(frozen=True)
class AccessRule(JSONSerializable):
    resource: str
    action: str
    filter: Optional[str] = None
