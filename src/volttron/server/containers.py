from __future__ import annotations

import inspect
import logging
import sys
import typing
from re import match
from typing import Optional, TypeVar, Union, get_type_hints

import returns
from returns.maybe import Maybe, Nothing, Some, maybe
from returns.pipeline import pipe
from returns.result import Failure, Result, Success

_log = logging.getLogger(__name__)

S = TypeVar('S')
T = TypeVar('T')


class Unresolvable(Exception):

    def __init__(self, type: T):
        super().__init__(f"Couldn't resolve type: {type} in container.")


class ResolutionError(Exception):
    pass


# Descriptor pattern from
class Frozen:
    __slots__ = ('private_name', )

    def __set_name__(self, owner, name):
        self.private_name = '_' + name

    def __get__(self, obj, objtype: T = None) -> T:
        value = getattr(obj, self.private_name)    # type:ignore
        return value

    def __set__(self, obj: T, value):
        if hasattr(obj, self.private_name):    # type:ignore
            msg = f'Attribute `{self.private_name[1:]}` is immutable!'
            raise TypeError(msg)

        setattr(obj, self.private_name, value)    # type:ignore


class Container:
    containers: dict[Container] = {}
    name: Frozen = Frozen()

    def start_services(self):
        pass

    class Resolvable:

        @property
        def type(self) -> T:
            raise NotImplementedError("type property must be implemented")

        @property
        def instance(self) -> S:
            raise NotImplementedError("instance property must be implemented")

        def resolve(self) -> Result[T, None]:
            raise NotImplementedError("resolve method must be implemented")

    # Container __init__
    def __init__(self, name: str = None) -> None:
        if name in self.containers:
            raise AttributeError(f"Container: {name} already exists and can't be modified.")
        self.name = name
        Container.containers[name] = self
        self._resolvable: dict[T, S] = {}
        self._resolvable_lists: dict[T, Container.ResolvableList] = {}

    def print_resolved(self, stream=sys.stdout):
        stream.write(f'{"-" * 80}\n')
        if self._resolvable_lists:
            stream.write("Lists\n")
            for r, v in self._resolvable_lists.items():
                stream.write(f"\t{r} -> {v}\n")
        else:
            stream.write("No Resolvable Lists Found")

        if self._resolvable:
            stream.write("Singletons")
            for r, v in self._resolvable.items():
                stream.write(f"\t{r}-> {v}\n")
            
        else:
            stream.write("No resolved items found")
        stream.write(f'{"-" * 80}\n')

    @staticmethod
    def destroy_all():
        for k, v in Container.containers.items():
            v._resolvable.clear()
        Container.containers.clear()

    @staticmethod
    def is_optional_type(field) -> bool:
        return typing.get_origin(field) is Union and \
            type(None) in typing.get_args(field)

    def _resolve_optional_argument(self, optional_field: T) -> Result[T, None]:

        for option in typing.get_args(optional_field):
            if option is not None:
                return option
            return next(filter(lambda l: l is not None, typing.get_args(optional_field)))

    def _resolve_argument(self, field: T) -> Result[T, None]:

        resolved = None
        if field in self._resolvable:
            container = self._resolvable[field]
            if isinstance(container, Container.Resolvable):
                resolved = container.resolve()
            else:
                resolved = Success(container)
        else:
            for k, v in self._resolvable.items():
                if isinstance(v, Container.ResolvableList):
                    if v.contains(field):
                        resolved = v.retrieve(field)
                        break
                    elif found_subclass := v.find_subclass(field):
                        return v.retrieve(found_subclass)

            if not resolved:
                if self.is_optional_type(field):
                    resolved = Success(None)
                else:
                    resolved = Failure(f"Couldn't resolve {field}")

            # resolved = Failure(f"Couldn't resolve {field}")
            # if isinstance(self._resolvable[field], Container.Singleton) or isinstance(
            #         self._resolvable[field], Container.Transient):
            #     _log.debug(f"For k: {k} using: {self._resolvable[field]._value} to resolve (.value) for.")
            #     self._kwargs[k] = self._resolvable[field].value
            # else:
            #     _log.debug(f"For k: {k} using: {self._resolvable[field]} to resolve (.value) for.")
            #     self._kwargs[k] = self._resolvable[field]
        return resolved

    def _resolve(self, field: T, **kwargs) -> Result[T, None]:

        found = self._resolvable.get(field)

        if not found:
            for k, v in self._resolvable_lists.items():
                if v.contains(field):
                    return v.retrieve(field)

                found_subclass = v.find_subclass(field)
                if found_subclass:
                    return v.retrieve(found_subclass)

        # If already found
        if found:
            if isinstance(found, Container.Resolvable):
                match found.resolve(**kwargs):
                    case Success(value):
                        return Success.from_value(value)
            elif isinstance(found, Container.ResolvableList):
                match found.retrieve(field, **kwargs):
                    case Success(value):
                        return Success.from_value(value)
            else:
                return Success.from_value(found)

        return Failure(None)

        # elif inspect.isclass(field):

        #     match self._resolve_arguments(field, **kwargs):
        #         case Success(value):
        #             if value == {}:
        #                 return Success.from_value(field())
        #             return Success.from_value(field(**value))
        #     for k, v in self._resolvable.items():
        #         if isinstance(v, Container.ResolvableList):
        #             if v.contains(field):
        #                 return v.retrieve(field)

        #     return Failure(f"Unable to resolve arguments to {field}.__init__")
        # elif Container.is_optional_type(field):
        #     return self._resolve_optional_argument(field)
        # else:
        #     return self._resolve_argument(field)

    def _resolve_arguments(self, fn: callable, **kwargs) -> Result[dict, None]:
        if inspect.isclass(fn):
            # TODO: get_type_hints returns all params.
            #  Add logic to skip optional args based on what is enabled
            #  i.e. auth related class can be missing if auth is not enabled
            required_args = get_type_hints(fn.__init__)
        else:
            required_args = get_type_hints(fn)
        resolved_kwargs = {}

        _log.debug(f"Required args are: {required_args}")
        if len(required_args) == 0:
            return Success({})

        for k, v in required_args.items():
            try:
                resolved_kwargs[k] = kwargs.pop(k)
            except KeyError:
                match self._resolve_argument(v):
                    case Success(value):
                        resolved_kwargs[k] = value
                    case Failure(_):
                        return Failure(f"Missing {k} argument")

        return Success(resolved_kwargs)

    class ResolvableList:

        def __init__(self, type: T):
            self._the_type = type
            self._resolvers: dict[S, Container.Singleton] = {}

        def find_subclass(self, type: T) -> Optional[S]:
            """Find subclass of type T in the resolvers.

            :param type: Type to search for
            :type type: T
            :return: The subclass if found or None
            :rtype: Optional[S]
            """
            for k, v in self._resolvers.items():
                if issubclass(k, type):
                    return k
            return None

        @property
        def type(self) -> T:
            return self._the_type

        def retrieve(self, type: S) -> Result[S, None]:
            if type not in self._resolvers:
                return Failure(None)
            return self._resolvers[type].resolve()

        def contains(self, type: S) -> bool:
            return type in self._resolvers

        def add_singleton(self, type: S, singleton: Container.Singleton):
            if type in self._resolvers:
                raise ValueError(
                    f"Can only have one resolver of {S} in ResolvableList of type {self._the_type}"
                )
            self._resolvers[type] = singleton

    class SingletonMulti:

        def __init__(self, value: Container.Singleton, **kwargs):
            _log.debug(f"Creating singlton value: {S} with kwargs: {kwargs}")
            self._value = value
            self._resolved = None
            self._kwargs = kwargs

        @property
        def value(self):
            if not self._resolved:
                self._resolved = self._value.ValueError
            return self._resolved

    class Singleton(Resolvable):

        def __init__(self, container: Container, value: S, **kwargs):
            _log.debug(f"Creating singlton value: {S} with kwargs: {kwargs}")
            self._value = value
            self._resolved = None
            self._kwargs = kwargs
            self._container: Container = container

            # self._kwargs = {k: v for k, v in kwargs.items()}

        @property
        def type(self) -> S:
            if not inspect.isclass(self._value):
                return type(self._value)
            return type(self._value)

        @property
        def instance(self) -> S:
            if self._resolved is not None:
                match self._container._resolve_arguments(self._value, **self._kwargs):
                    case Success(value):
                        self._resolved = value
                    case Failure(_):
                        raise Unresolvable(self._value)

        @property
        def value(self) -> Maybe[S]:
            if not self._resolved:
                _log.debug(f"Resolving: {self._value}")
                self._resolved = self.resolved(**self._kwargs)
            return self._resolved

        def resolve(self) -> Result[S, None]:
            if not self._resolved:
                self._resolved = self._do_resolution()

            if not self._resolved:
                return Failure(None)

            return Success(self._resolved)

        def _do_resolution(self, **kwargs) -> Result[S, None]:
            if not self._resolved:
                self._kwargs.update(kwargs)
                if 'kwargs' in self._kwargs and self._kwargs['kwargs'] == {}:
                    del self._kwargs['kwargs']

                # Look for args that can be satisfied by looking up
                # the resovable services.
                resolved_kwargs: Result[dict, None] = self._container._resolve_arguments(
                    self._value.__init__, **self._kwargs)
                if isinstance(resolved_kwargs, Failure):
                    raise ResolutionError(str(resolved_kwargs))
                # required_args = get_type_hints(self._value.__init__)

                # _log.debug(f"Required args are: {required_args}")
                # for k, v in required_args.items():
                #     non_none_type = v

                #     # Handle optional
                #     if typing.get_origin(v) == typing.Union and len(typing.get_args(v)) > 2:
                #         raise ResolutionError(f"Argument {v} to resolve {k} has more than 2 types")
                #     elif typing.get_origin(v) == typing.Union and None not in typing.get_args(v):
                #         raise ResolutionError(
                #             f"Argument {v} to resolve {k} only None and one more type is allowed to resolve")
                #     elif typing.get_origin(v) == typing.Union:
                #         non_none_type = next(filter(lambda l: l is not None, typing.get_args(v)))

                #     if non_none_type in self._resolvable:
                #         if isinstance(self._resolvable[non_none_type], Container.Singleton) or isinstance(
                #                 self._resolvable[non_none_type], Container.Transient):
                #             _log.debug(
                #                 f"For k: {k} using: {self._resolvable[non_none_type]._value} to resolve (.value) for.")
                #             self._kwargs[k] = self._resolvable[non_none_type].value
                #         else:
                #             _log.debug(f"For k: {k} using: {self._resolvable[non_none_type]} to resolve (.value) for.")
                #             self._kwargs[k] = self._resolvable[non_none_type]

                try:
                    arg_dict = resolved_kwargs.unwrap()
                    self._resolved = self._value(**resolved_kwargs.unwrap())
                except TypeError as ex:
                    for x in ex.args:
                        if 'kwargs' in x or 'no arguments' in x:
                            self._resolved = self._value()
                            break
                    if not self._resolved:
                        raise ex

            return self._resolved

    class Transient:

        def __init__(self, value: S, **kwargs):
            self._value = value
            self._kwargs = kwargs

        @property
        def value(self):
            return self._resolve_kwargs(**self._kwargs)
            # return self._value(**self._kwargs)

        def _resolve_kwargs(self, **kwargs) -> S:
            # Look for args that can be satisfied by looking up
            # the resovable services.
            required_args = get_type_hints(self._value.__init__)

            my_kwargs = kwargs
            ret_value: S = None

            for k, v in required_args.items():
                to_resolve = v
                if Container.is_optional_type(v):
                    if len(typing.get_args(v)) > 2:
                        raise ValueError("Only support optional of single values")
                    for option in typing.get_args(v):
                        if option is not None:
                            to_resolve = option
                            break
                    _log.debug(f"k: {k} is optional {typing.get_origin(v)}")
                if to_resolve in self._resolvable:
                    if isinstance(self._resolvable[to_resolve], Container.Singleton) or isinstance(
                            self._resolvable[to_resolve], Container.Transient):
                        _log.debug(
                            f"For k: {k} using: {self._resolvable[to_resolve]._value} to resolve (.value) for."
                        )
                        self._kwargs[k] = self._resolvable[to_resolve].value
                    else:
                        _log.debug(
                            f"For k: {k} using: {self._resolvable[to_resolve]} to resolve (.value) for."
                        )
                        self._kwargs[k] = self._resolvable[to_resolve]

            try:
                ret_value = self._value(**self._kwargs)
            except TypeError as ex:
                for x in ex.args:
                    if 'kwargs' in x:
                        ret_value = self._value()
                        break
                if not ret_value:
                    raise ex
            return ret_value

    # def add_singleton_with_many(self, type: T, value: S, **kwargs: dict):
    # def add_singleton_by_name()

    def add_interface_reference(self, type: T, value: S, **kwargs: dict):
        """
        Add a reference where type T resolves to value S.  In this case the type can
        be a Protocol, BaseClass or any class which value: S implements.  And will be
        resolvable only by resolve(T).

        :param type: An interface for using to resolve to
        :type type: T
        :param value: An object instance or resolvable class for interface retrieval.
        :type value: S
        :raises AttributeError: Raised if a type T already has been added to the resolved items.
        """
        if type in self._resolvable:
            raise AttributeError(f"Type: {type} already exists and can't be modified.")
        self._resolvable[type] = Container.Singleton(self, value, **kwargs)

    def add_concrete_reference(self, type: T, value: S, **kwargs: dict):

        resolvable_list: Container.ResolvableList = None
        if type in self._resolvable:
            if not isinstance(self._resolvable[type], Container.ResolvableList):
                raise AttributeError(f"{type} already found as an instance_reference.")
            resolvable_list: Container.ResolvableList = self._resolvable[type]
            if resolvable_list.contains(value):
                raise ValueError(f"{value} already within the resolvable list type {T} ")
        else:
            resolvable_list = Container.ResolvableList(type=type)
            self._resolvable[type] = resolvable_list
        if not type in self._resolvable_lists:
            self._resolvable_lists[type] = resolvable_list
        resolvable_list.add_singleton(value, Container.Singleton(self, value, **kwargs))

    def add_instance(self, type: T, value: S):
        self._resolvable[type] = value

    def add_factory(self, type: T, value: S, **kwargs):
        self._resolvable[type] = Container.Transient(value, **kwargs)

    def resolve(self, type: T, **kwargs) -> Optional[S]:
        _log.debug(f"Attempting resolve of type: {type}")

        match self._resolve(type, **kwargs):
            case Success(value):
                self._resolvable[type] = value
                return value
            case Failure(_):
                raise Unresolvable(type)

        return None

        resolved = pipe(self._resolve)
        return resolved(type)

        try:
            unwrapped = resolved.unwrap()
            if unwrapped is None:
                raise Unresolvable(type=type)
            else:
                return unwrapped
        except returns.primitives.exceptions.UnwrapFailedError:
            raise Unresolvable(type=type)

        return resolved.unwrap_or(None)

        try:
            resolved: Maybe = None
            obj = self.resolvable[type]
            if isinstance(obj, Container.Transient):
                resolved = obj.resolve()
                return obj.value()
            elif isinstance(obj, Container.Singleton):
                return obj.resolved()
            return self.resolvable[type]
        except KeyError:
            for k, v in self.resolvable.items():
                if isinstance(v, self._resolvableList):
                    if v.contains(type):
                        return v.retrieve(type)
            raise Unresolvable(type=type)

    @staticmethod
    def create(name: str) -> Container:
        if name in Container.containers:
            raise ValueError(f"A container named: {name} already exists")
        container = Container(name=name)
        Container.containers[name] = container
        return container

    @staticmethod
    def get_container(name: str) -> Container:
        return Container.containers[name]


service_repo = Container()
