import json
import os
from pathlib import Path
import importlib
from typing import Type, Optional

from . import MessageBusConfig

def get_system_messagebus_registry() -> dict:
    """
    Get the system-wide messagebus registry from ~/.local/share/volttron
    
    Returns:
        dict: Mapping of messagebus names to config class paths
    """
    # Use the same path calculation as in the registration module
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config:
        base_dir = Path(xdg_config)
    else:
        base_dir = Path.home() / ".local" / "share"
    
    registry_path = base_dir / "volttron" / "messagebus_registry.json"
    
    if registry_path.exists():
        try:
            with open(registry_path) as f:
                return json.load(f)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Error reading messagebus registry: {e}")
    
    return {}

def get_messagebus_config_class(messagebus_type: str) -> Optional[Type[MessageBusConfig]]:
    """
    Get the appropriate config class for a messagebus type using the registry
    
    Checks both the system-wide registry and volttron_home registry.
    
    Args:
        messagebus_type: String identifier for the messagebus (e.g., "zmq", "rmq")
        
    Returns:
        The config class or None if not found
    """
    # Check system registry first
    system_registry = get_system_messagebus_registry()
    class_path = None
    
    if messagebus_type in system_registry:
        class_path = system_registry[messagebus_type]
    
    # Also check instance-specific registry if system one didn't have it
    if not class_path:
        volttron_home = os.environ.get('VOLTTRON_HOME')
        if volttron_home:
            instance_registry_path = Path(volttron_home) / "messagebus_registry.json"
            if instance_registry_path.exists():
                try:
                    with open(instance_registry_path) as f:
                        instance_registry = json.load(f)
                        if messagebus_type in instance_registry:
                            class_path = instance_registry[messagebus_type]
                except Exception:
                    pass
    
    # If we found a class path, load the class
    if class_path:
        try:
            module_path, class_name = class_path.rsplit(".", 1)
            module = importlib.import_module(module_path)
            return getattr(module, class_name)
        except (ImportError, AttributeError) as e:
            import logging
            logging.getLogger(__name__).error(f"Error loading messagebus config class {class_path}: {e}")
    
    return None