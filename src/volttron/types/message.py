from dataclasses import dataclass
from typing import List


@dataclass
class Message:
    peer: str
    subsystem: str
    id: str
    args: List
