from __future__ import annotations    # Allows reference to current class

from abc import ABC, abstractmethod, abstractstaticmethod
from dataclasses import dataclass
from typing import Protocol, runtime_checkable
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

    @property
    def type(self):
        return self.__class__

    def create(*, identity: str, publickey: str, secretkey: str) -> PKICredentials:
        return PKICredentials(identity=identity, publickey=publickey, secretkey=secretkey)

    def create_with_generator(*, identity: str, generator_fn: callable) -> PKICredentials:
        publickey, secretkey = generator_fn()
        return PKICredentials(identity=identity, publickey=publickey, secretkey=secretkey)


class CredentialsFactory:

    @staticmethod
    def create_from_file(identity: str, path: Path | str) -> Credentials:
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
        if path is str:
            path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Credential file: {path.as_posixs()} not found!")

        obj = jsonapi.load(path.open())

        # TODO: Handle this better using type within the keystore.json file.
        if "public" in obj and "secret" in obj:
            return PKICredentials.create(identity=identity,
                                         publickey=obj["public"],
                                         secretkey=obj["secret"])
        else:
            return Credentials.create(identity=identity)


class CredentialsCreator(ABC):

    @abstractmethod
    def create(*, identity: str, **kwargs) -> Credentials:
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
    def retrieve_credentials(self, *, identity: str) -> Credentials:
        """
        Retrieve the credentials for an identity.

        :param identity: The identity to retrieve credentials for.
        :type identity: str
        :return: The stored credentials.
        :rtype: Credentials
        :raises: IdentityNotFound: If the identity does not exist, an IdentityNotFound exception MUST be raised.
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
