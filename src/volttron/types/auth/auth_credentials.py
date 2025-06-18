from __future__ import annotations    # Allows reference to current class

from abc import ABC, abstractmethod, abstractstaticmethod
from dataclasses import dataclass
from typing import Protocol, runtime_checkable
import os
from pathlib import Path

from dataclass_wizard import JSONSerializable

from volttron.utils import jsonapi


class CredentialStoreError(Exception):
    pass


class IdentityNotFound(Exception):
    pass


class IdentityAlreadyExists(Exception):
    pass


class InvalidCredentials(Exception):
    pass


@dataclass(frozen=True, kw_only=True)
class Credentials(JSONSerializable):
    identity: str

    def create(*, identity: str) -> Credentials:
        return Credentials(identity=identity)


@dataclass(frozen=True, kw_only=True)
class PublicCredentials(Credentials):
    publickey: str

    def create(*, identity: str, publickey: str) -> PublicCredentials:
        return PublicCredentials(identity=identity, publickey=publickey)


@dataclass(frozen=True, kw_only=True)
class PKICredentials(PublicCredentials):
    secretkey: str

    def get_public_part(self) -> str:
        """
        Returns the public part of the PKI credentials as a dictionary.
        """
        return self.publickey

    @property
    def type(self):
        return self.__class__

    def create(*, identity: str, publickey: str, secretkey: str) -> PKICredentials:
        return PKICredentials(identity=identity, publickey=publickey, secretkey=secretkey)

    def create_with_generator(*, identity: str, generator_fn: callable) -> PKICredentials:
        publickey, secretkey = generator_fn()
        return PKICredentials(identity=identity, publickey=publickey, secretkey=secretkey)


@dataclass(frozen=True, kw_only=True)
class VolttronCredentials(PKICredentials):
    domain: str = 'VIP'
    address: str = ''

    @property
    def type(self):
        return self.__class__

    @staticmethod
    def load_from_file(filename: str | Path) -> Credentials:

        if filename is None:
            raise ValueError(f"filename cannot be None")

        if isinstance(filename, str):
            filename = Path(filename).expanduser()

        filename = filename.absolute()

        if not filename.exists():
            raise ValueError(f"filename: {filename} does not exist.")

        obj = jsonapi.loads(filename.read_text())

        return VolttronCredentials.from_dict(obj)


# @service
class CredentialsFactory:
    # def __init__(self, server_options: ServerOptions):
    #     server_options.
    #     CredentialsFactory.CREDENTIAL_STORE = os.environ

    @staticmethod
    def load_from_environ() -> Credentials:
        if credentials := os.environ.get("AGENT_CREDENTIALS"):
            # Expand user variables
            credentials = os.path.expanduser(credentials)
            try:
                creds = CredentialsFactory.load_credentials_from_file(credentials)
                return creds
            except FileNotFoundError:

                # Attempt to load from the environmental variable.
                obj = jsonapi.loads(credentials)

                creds = VolttronCredentials.from_dict(obj)
                return creds

        raise ValueError("No AGENT_CREDENTIALS Environmental Variable")

    @staticmethod
    def load_credentials_from_file(path: Path | str) -> Credentials:
        """
        Create a `Credentials` object from the specified path.

        This function reads from a file and attempts to parse and load the Credentials
        object from that file.  We only support json based credential files.  If the
        credential file holds a public and secret attribute key then a PublicKeyCredential is
        loaded, otherwise a basic Credentials object is loaded.

        :param identity: The identity that should be passed into the Credentals
        :type identity: str
        :param path: A path for the Credentials to load from
        :type path: Path | str
        :raises FileNotFoundError: If path does not exist.
        :return: A credentials object or raises an exception.
        :rtype: Credentials
        """
        if isinstance(path, str):
            path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Credential file: {path} not found!")

        obj = jsonapi.load(path.open())

        # TODO: Handle this better using type within the keystore.json file.
        if "publickey" in obj and "secretkey" in obj:
            return PKICredentials.create(identity=obj["identity"],
                                         publickey=obj["publickey"],
                                         secretkey=obj["secretkey"])
        else:
            return Credentials.create(identity=obj["identity"])


class CredentialsCreator(ABC):

    @abstractmethod
    def create(self, *, identity: str, **kwargs) -> Credentials:
        ...

    # def delete(*, identity: str) -> None:
    #     ...

    # def getall() -> list[Credentials]:
    #     ...


class DefaultCredentialsFactory(CredentialsCreator):

    def create(*, identity: str) -> Credentials:
        return Credentials(identity=identity)


class DefaultPKICredentialsFactory(CredentialsCreator):

    def create(*, identity: str, publickey: str, secretkey: str) -> Credentials:
        return PKICredentials(identity=identity, publickey=publickey, secretkey=secretkey)


class CredentialsStore(ABC):

    @abstractmethod
    def get_credentials_type(self) -> type:
        ...

    @abstractmethod
    def store_credentials(self, *, credentials: Credentials) -> None:
        """
        Store credentials for an identity.

        :param identity: The identity to store credentials for.
        :type identity: str
        :param credentials: The credentials to store.
        :type credentials: Credentials
        :raises: IdentityAlreadyExists: If the identity alredy exists, an IdentityAlreadyExists exception MUST be raised.
        """
        ...

    @abstractmethod
    def retrieve_credentials(self, **kwargs) -> Credentials | None:
        """
        Retrieve credentials based upon passed criteria.

        It is up to the implementor to make sure that the passed kwargs are
        processed correctly and return the correct response.
        """
        ...

    @abstractmethod
    def remove_credentials(self, *, identity: str) -> None:
        """
        Delete the credentials for an identity.

        :param identity: The identity to delete credentials for.
        :type identity: str
        :raises: IdentityNotFound: If the identity does not exist, an IdentityNotFound exception MUST be raised.
        """
        ...
