from dataclasses import dataclass
from typing import Any


@dataclass
class Parameter:
    key: str
    value: Any