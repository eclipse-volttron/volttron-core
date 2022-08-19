from configparser import ConfigParser
import logging
import os

from volttron.utils import ClientContext as cc

_log = logging.getLogger(__name__)


def store_message_bus_config(message_bus, instance_name):
    # If there is no config file or home directory yet, create volttron_home
    # and config file
    if not instance_name:
        raise ValueError("Instance name should be a valid string and should "
                         "be unique within a network of volttron instances "
                         "that communicate with each other. start volttron "
                         "process with '--instance-name <your instance>' if "
                         "you are running this instance for the first time. "
                         "Or add instance-name = <instance name> in "
                         "vhome/config")

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
