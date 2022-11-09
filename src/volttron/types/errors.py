from typing import Any


class NotFoundError(Exception):
    def __init__(self, key: str, context: Any = None):
        self._key = key
        self._context = context

    def __str__(self):
        if self._context:
            return f"{self._key} was not found in {self._context}."
        else:
            return f"{self._key} was not found."


class MessageBusConnectionError(Exception):
    pass
