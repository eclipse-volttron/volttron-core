import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from volttron.client.known_identities import CONTROL_CONNECTION


class CredentialsExistError(Exception):
    def __init__(self, identity: str):
        self._identity = identity

    def __str__(self):
        return f"Credentials already exist for {self._identity}."


class CredentialsError(Exception):
    def __init__(self, identity: str):
        self._identity = identity

    def __str__(self):
        return f"Credentials for {self._identity} not found."


@dataclass
class Credentials:
    identifier: str
    type: str
    credentials: Any

    @staticmethod
    def from_environment(volttron_home: str, identity: str):
        # Lookup credentials based upon environmental message bus etc.
        # TODO allow this to be generalized for whatever path is necessary or whatever is necessary to get credentials
        if identity == CONTROL_CONNECTION:
            cred_store_path = Path(f"{volttron_home}/credential_store/{identity}.json")
            if not cred_store_path.exists():
                raise CredentialsError(identity)
        data = json.loads(Path(volttron_home).joinpath().read_text())
        return Credentials(identifier=identity, type="zmq", credentials=json.dumps(data))


class CredentialsGenerator:
    @staticmethod
    def generate(identity: str) -> Credentials:
        raise NotImplementedError()


class CredentialsManager:

    def load(self, identity: str) -> Credentials:
        raise NotImplementedError()

    def store(self, credentials: Credentials):
        raise NotImplementedError()
