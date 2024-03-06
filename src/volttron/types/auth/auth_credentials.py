from __future__ import annotations    # Allows reference to current class

from abc import ABC, abstractmethod, abstractstaticmethod
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from dataclass_wizard import JSONSerializable


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
