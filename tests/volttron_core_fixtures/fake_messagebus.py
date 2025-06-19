from abc import abstractmethod
from typing import Any

from volttron.types import MessageBus, MessageBusConfig


from typing import Any, Optional

from volttron.types import MessageBus, Message, FederationBridge

class FakeMessageBusConfig(MessageBusConfig):
    """Test implementation - simulates third-party messagebus config"""
    
    def __init__(self, instance_name: str, **kwargs):
        super().__init__() if hasattr(super(), '__init__') else None
        
        self.instance_name = instance_name
        self.address = kwargs.get("address", [])
        self.test_mode = kwargs.get("test_mode", True)
        self.connection_timeout = kwargs.get("connection_timeout", 30)
        # Add the missing test_parameter
        self.test_parameter = kwargs.get("test_parameter", "default_value")
    
    @classmethod
    def get_defaults(cls) -> dict[str, Any]:
        """Return default configuration values"""
        return {
            "test_mode": True,
            "connection_timeout": 30,
            "test_parameter": "default_value",  # Add this
            "address": ["fake://127.0.0.1:12345"]
        }
    
    @classmethod
    def create_from_options(cls, options_dict: dict[str, Any]) -> MessageBusConfig:
        """Create config instance from options dict"""
        # Merge with defaults
        defaults = cls.get_defaults()
        merged_options = {**defaults, **options_dict}
        
        # Extract required instance_name
        instance_name = merged_options.pop("instance_name")
        
        return cls(instance_name=instance_name, **merged_options)

class FakeMessageBus(MessageBus):
    """Test MessageBus implementation"""
    
    def __init__(self, config: FakeMessageBusConfig):
        self.config = config
        self._running = False
        self._messages = []
        self._stop_handler = None # type: ignore
    
    def create_federation_bridge(self) -> Optional[FederationBridge]:
        return None
    
    def start(self):
        self._running = True
    
    def stop(self):
        self._running = False
        if self._stop_handler:
            self._stop_handler.message_bus_shutdown()
    
    def is_running(self) -> bool:
        return self._running
    
    def send_vip_message(self, message: Message):
        self._messages.append(message)
    
    def receive_vip_message(self) -> Message:
        return self._messages.pop(0) if self._messages else None # type: ignore