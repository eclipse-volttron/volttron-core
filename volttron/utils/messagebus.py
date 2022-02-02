from configparser import ConfigParser
import logging
import os

from ..utils import ClientContext as cc

_log = logging.getLogger(__name__)


def store_message_bus_config(message_bus, instance_name):
    # If there is no config file or home directory yet, create volttron_home
    # and config file
    if not instance_name:
        raise ValueError(
            "Instance name should be a valid string and should "
            "be unique within a network of volttron instances "
            "that communicate with each other. start volttron "
            "process with '--instance-name <your instance>' if "
            "you are running this instance for the first time. "
            "Or add instance-name = <instance name> in "
            "vhome/config"
        )

    v_home = cc.get_volttron_home()
    config_path = os.path.join(v_home, "config")
    if os.path.exists(config_path):
        config = ConfigParser()
        config.read(config_path)
        config.set("volttron", "message-bus", message_bus)
        config.set("volttron", "instance-name", instance_name)
        with open(config_path, "w") as configfile:
            config.write(configfile)
    else:
        if not os.path.exists(v_home):
            os.makedirs(v_home, 0o755)
        config = ConfigParser()
        config.add_section("volttron")
        config.set("volttron", "message-bus", message_bus)
        config.set("volttron", "instance-name", instance_name)

        with open(config_path, "w") as configfile:
            config.write(configfile)
        # all agents need read access to config file
        os.chmod(config_path, 0o744)


def update_kwargs_with_config(kwargs, config):
    """
    Loads the user defined configurations into kwargs.

      1. Converts any dash/hyphen in config variables into underscores
      2. Checks for configured "identity" value. Prints a deprecation
      warning and uses it.
      3. Checks for configured "agentid" value. Prints a deprecation warning
      and ignores it

    :param kwargs: kwargs to be updated
    :param config: dictionary of user/agent configuration
    """

    if config.get("identity") is not None:
        _log.warning(
            "DEPRECATION WARNING: Setting a historian's VIP IDENTITY"
            " from its configuration file will no longer be supported"
            " after VOLTTRON 4.0"
        )
        _log.warning(
            "DEPRECATION WARNING: Using the identity configuration setting "
            "will override the value provided by the platform. This new value "
            "will not be reported correctly by 'volttron-ctl status'"
        )
        _log.warning(
            "DEPRECATION WARNING: Please remove 'identity' from your "
            "configuration file and use the new method provided by "
            "the platform to set an agent's identity. See "
            "scripts/core/make-mongo-historian.sh for an example of "
            "how this is done."
        )

    if config.get("agentid") is not None:
        _log.warning(
            "WARNING: Agent id cannot be configured. It is a unique "
            "id assigned by VOLTTRON platform. Ignoring configured "
            "agentid"
        )
        config.pop("agentid")

    for k, v in config.items():
        kwargs[k.replace("-", "_")] = v
