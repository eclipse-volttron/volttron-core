import argparse
import configparser
import logging
import os
import socket
from collections import OrderedDict
from configparser import ConfigParser
from dataclasses import dataclass, field, fields
from pathlib import Path

_log = logging.getLogger(__name__)

class MultiOrderedDict(OrderedDict):

    def __setitem__(self, key, value):
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super(MultiOrderedDict, self).__setitem__(key, value)


@dataclass
class ServerOptions:
    """
    A data class representing the configuration options for a Volttron platform server.

    :ivar volttron_home: The path to the root directory of the Volttron instance.
                         Default is '~/.volttron', which is expanded to the current user's home directory.
    :vartype volttron_home: Union[pathlib.Path, str]

    :ivar instance_name: The name of the Volttron instance. Default is the hostname of the machine.
    :vartype instance_name: str

    :ivar address: A list of addresses on which the platform should listen for incoming connections.
                     Default is None.
    :vartype address: List[str]

    :ivar agent_isolation_mode: Flag indicating whether the agent isolation mode is enabled.
                                Default is False.
    :vartype agent_isolation_mode: bool

    :ivar message_bus: The fully-qualified name of the message bus class to use. Default is
                       'volttron.messagebus.zmq.ZmqMessageBus'.
    :vartype message_bus: str

    :ivar agent_core: The fully-qualified name of the agent core class to use. Default is
                      'volttron.messagebus.zmq.ZmqCore'.
    :vartype agent_core: str

    :ivar auth_service: The fully-qualified name of the authentication service class to use. Default is
                        'volttron.services.auth'.
    :vartype auth_service: str

    :ivar service_config: The Path to the service config file for loading services into the context.
    :vartype service_service: Path
    """
    volttron_home: Path | None = None
    instance_name: str | None = None
    local_address: str | None = None
    address: list[str] = field(default_factory=list)
    agent_isolation_mode: bool = False
    # Module that holds the zmq based classes, though we shorten it assuming
    # it's in volttron.messagebus
    messagebus: str = "zmq"
    auth_enabled: bool = True
    config_file: Path | None = None
    initialized: bool = False
    service_address: str | None = None
    server_messagebus_id: str = "vip.server"
    agent_monitor_frequency: int = 30
    poetry_project_path: Path | None = None
    enable_federation: bool = False
    federation_url: str | None  = None
    

    def __post_init__(self):
        """
        Initializes the instance after it has been created.

        If `volttron_home` is a string, it is converted to a `pathlib.Path` object.

        If `instance_name` is None, it is set to the hostname of the machine.
        """

        if self.volttron_home is None:
            self.volttron_home = Path(os.environ.get("VOLTTRON_HOME", "~/.volttron")).expanduser()

        if self.poetry_project_path is None:
            self.poetry_project_path = self.volttron_home

        if isinstance(self.volttron_home, str):
            self.volttron_home = Path(self.volttron_home).absolute()
            
        # Should be the only location where we create VOLTTRON_HOME
        if not self.volttron_home.is_dir():
            self.volttron_home.mkdir(mode=0o755, exist_ok=True, parents=True)

        if self.config_file is None:
            self.config_file = self.volttron_home / "config"

        # TODO: This should be removed once we have a better way of handling
        if self.service_address is None:
            self.service_address = "inproc://vip"

        # Allow the config path to be whereever the user wants it to be.
        if not self.config_file.exists():
            self.config_file.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            if self.instance_name is None:
                self.instance_name = socket.gethostname()

            if isinstance(self.address, str):
                self.address = [self.address]

        else:
            if not self.initialized:
                options = ServerOptions.from_file(self.config_file)

                for fld in ServerOptions.__dataclass_fields__:
                    setattr(self, fld, getattr(options, fld))

    from volttron.types import MessageBusConfig
    def get_messagebus_config(self) -> MessageBusConfig:
        """
        Get messagebus configuration using the global registry system
        
        Returns:
            MessageBusConfig: Configured messagebus instance
        """
        from volttron.types.messagebus import get_messagebus_config_class
        
        # Get messagebus type from config file or default to zmq
        messagebus_type = self.messagebus
        if not messagebus_type:
            # Check config file for messagebus setting
            config_file = self.volttron_home / "config"
            if config_file.exists():
                from configparser import ConfigParser
                config = ConfigParser()
                config.read(config_file)
                if config.has_option("volttron", "messagebus"):
                    messagebus_type = config.get("volttron", "messagebus")
            
            # Default to zmq if nothing specified
            messagebus_type = messagebus_type or "zmq"
        
        # Load config class from global registry
        config_class = get_messagebus_config_class(messagebus_type)
        if not config_class:
            raise ValueError(
                f"Unknown messagebus type '{messagebus_type}'. "
                f"Make sure the appropriate messagebus library is installed and registered."
            )
        
        # Create configuration with server options
        options = {
            "instance_name": self.instance_name,
            "volttron_home": str(self.volttron_home),
            "address": self.address,
            "local_address": self.local_address,
            "enable_federation": self.enable_federation,
            "federation_url": self.federation_url,
            "auth_enabled": self.auth_enabled,
            "service_address": self.service_address,
            "agent_monitor_frequency": self.agent_monitor_frequency
        }

    # volttron_home: Path | None = None
    # instance_name: str | None = None
    # local_address: str | None = None
    # address: list[str] = field(default_factory=list)
    # agent_isolation_mode: bool = False
    # # Module that holds the zmq based classes, though we shorten it assuming
    # # it's in volttron.messagebus
    # messagebus: str = "zmq"
    # auth_enabled: bool = True
    # config_file: Path | None = None
    # initialized: bool = False
    # service_address: str | None = None
    # server_messagebus_id: str = "vip.server"
    # agent_monitor_frequency: int = 30
    # poetry_project_path: Path | None = None
    # enable_federation: bool = False
    # federation_url: str | None  = None
        
        return config_class.create_from_options(options)
    
    def update(self, opts: argparse.Namespace | dict):
        """Update the opts from the passed command line or a dictionary.

        :param opts: Parameters passed from the command line or a dictionary form volttron testing framework.
        :type opts: argparse.Namespace | dict
        """
        address = set(opts.address)
        opts.address = list(address)

        if isinstance(opts, dict):
            dev_mode = opts.pop("dev_mode")
            self.__dict__.update(opts)
        else:
            d = opts.__dict__
            dev_mode = d.pop("dev_mode")
            self.__dict__.update(d)

        if dev_mode:
            self.poetry_project_path = Path(os.path.abspath(os.curdir))

    def store(self, file: Path = None):
        """
        Stores the current configuration options to a file.

        :param file: The path to the file where the configuration options should be stored.
        :type file: Union[pathlib.Path, str]
        """
        parser = ConfigParser(dict_type=MultiOrderedDict, strict=False)

        parser.add_section("volttron")

        kwargs = {}

        services_field = None
        # Store the config options first.
        for field in fields(ServerOptions):
            try:
                # Don't save volttron_home within the config file.
                if field.name not in ('volttron_home', 'services', 'config_file', 'initialized', 'service_address',
                                      "poetry_project_path", "local_address"):
                    # More than one address can be present, so we must be careful
                    # with it.
                    if field.name == 'address':
                        found = set()
                        for v in getattr(self, field.name):
                            if v not in found:
                                parser.set("volttron", "address", value=v)
                                found.add(v)
                        # for v in getattr(self, field.name):
                        #     parser.set("volttron", "address", v)
                    else:
                        parser.set("volttron", field.name.replace('_', '-'), str(getattr(self, field.name)))
            except configparser.NoOptionError:
                pass

        # TODO Add services back in.
        # parser.add_section('services')
        # for sd in self.services:
        #     parser.set("services", sd.identity, sd.klass_path)

        #     if sd.args:
        #         parser.add_section(sd.klass_path)
        #         for arg, value in sd.args:
        #             parser.set(sd.klass_path, arg, value)

        if file is None:
            file = self.config_file
        parser.write(file.open("w"))

    @staticmethod
    def from_file(file: Path | str = None):
        """
        Creates a `ServerOptions` instance from a file.

        If `file` is None, the default file location ('$VOLTTRON_HOME/config') is used.

        :param file: The path to the file containing the configuration options.
        :type file: Optional[Union[pathlib.Path, str]]

        :returns: A `_ServerOptions` instance created from the file.
        :rtype: _ServerOptions
        """
        if file is None:
            if os.environ.get('VOLTTRON_HOME'):
                file = Path(os.environ.get('VOLTTRON_HOME')).expanduser() / "config"
            else:
                file = Path("~/.volttron/config").expanduser()

        if isinstance(file, str):
            file = Path(file)

        if file.exists():
            parser = ConfigParser(strict=False)
            parser.read(file)

            kwargs = {}

            for field in fields(ServerOptions):
                try:
                    value = parser.get(section="volttron", option=field.name.replace('_', '-'))
                    if value == 'None':
                        value = None
                    elif value == 'False' or value == 'True':
                        value = eval(value)
                    elif field.name == 'service_config' or field.name == 'volttron_home':
                        value = Path(value)
                    elif field.name == 'address':
                        value = value.split('\n')
                    kwargs[field.name] = value
                except configparser.NoOptionError:
                    pass
            kwargs['initialized'] = True
            options = ServerOptions(**kwargs)
        else:
            options = ServerOptions()
            options.store(file)

        return options
