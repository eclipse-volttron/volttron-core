# tests/unit/test_messagebus_config.py
import json
import os
import pytest
from pathlib import Path
from typing import Any

from volttron.types import MessageBusConfig
from volttron_core_fixtures.fake_messagebus import FakeMessageBus, FakeMessageBusConfig


class ServerOptionsStubForTesting:
    """A simplified stub of ServerOptions for testing"""
    
    def __init__(self, **kwargs):
        self.instance_name = kwargs.get("instance_name", "test-instance")
        self.address = kwargs.get("address", ["fake://127.0.0.1:12345"])
        self.message_bus = kwargs.get("message_bus", "fake")
    
    def get_messagebus_config(self) -> dict[str, Any]:
        """Extract message bus configuration"""
        return {
            "instance_name": self.instance_name,
            "address": self.address
        }


class TestMessageBusConfig:
    
    def test_base_config_interface(self):
        """Test that base class defines proper interface"""
        # Test that it's abstract/has expected methods
        assert hasattr(MessageBusConfig, 'get_defaults')
        assert hasattr(MessageBusConfig, 'create_from_options')
    
    def test_fake_config_implements_interface(self):
        """Test that FakeMessageBusConfig properly implements interface"""
        assert issubclass(FakeMessageBusConfig, MessageBusConfig)
        assert hasattr(FakeMessageBusConfig, 'get_defaults')
        assert hasattr(FakeMessageBusConfig, 'create_from_options')
        assert callable(FakeMessageBusConfig.get_defaults)
        assert callable(FakeMessageBusConfig.create_from_options)
    
    def test_create_from_options_merges_defaults(self):
        """Test that create_from_options properly merges with defaults"""
        options = {
            "instance_name": "test-merge",
            "connection_timeout": 120  # Override default
        }
        
        config = FakeMessageBusConfig.create_from_options(options)
        
        assert config.instance_name == "test-merge"
        assert config.connection_timeout == 120  # Overridden
        assert config.test_mode is True  # From defaults
    
    def test_create_from_options_with_defaults(self):
        """Test creation of config from options with defaults applied"""
        options_dict = {
            "instance_name": "test-instance"
        }
        
        config = FakeMessageBusConfig.create_from_options(options_dict)
        
        assert config.instance_name == "test-instance"
        assert config.test_mode is True  # From defaults
        assert config.test_parameter == "default_value"  # From defaults
        assert "fake://127.0.0.1:12345" in config.address  # From defaults
    
    def test_create_from_options_with_overrides(self):
        """Test creation of config with options overriding defaults"""
        options_dict = {
            "instance_name": "custom-instance",
            "test_mode": False,
            "test_parameter": "custom_value",
            "address": ["fake://192.168.1.1:54321"]
        }
        
        config = FakeMessageBusConfig.create_from_options(options_dict)
        
        assert config.instance_name == "custom-instance"
        assert config.test_mode is False  # Overridden
        assert config.test_parameter == "custom_value"  # Overridden
        assert config.address == ["fake://192.168.1.1:54321"]  # Overridden
    
    def test_messagebus_initialization(self):
        """Test initializing a message bus with configuration"""
        options_dict = {
            "instance_name": "init-test-instance",
            "test_parameter": "initialization_test"
        }
        
        config = FakeMessageBusConfig.create_from_options(options_dict)
        message_bus = FakeMessageBus(config)
        
        assert message_bus.config.instance_name == "init-test-instance"
        assert message_bus.config.test_parameter == "initialization_test"
        assert message_bus.is_running() is False
    
    def test_messagebus_registry_integration(self, tmp_path):
        """Test integration with a message bus registry"""
        # Mock volttron_home for testing
        volttron_home = tmp_path / ".volttron"
        volttron_home.mkdir()
        
        # Create test registry
        registry = {
            "fake": "volttron_core_fixtures.fake_messagebus.FakeMessageBusConfig"
        }
        
        registry_path = volttron_home / "messagebus_registry.json"
        with open(registry_path, 'w') as f:
            json.dump(registry, f)
        
        # Test loading from registry
        original_home = os.environ.get("VOLTTRON_HOME")
        try:
            os.environ["VOLTTRON_HOME"] = str(volttron_home)
            
            # Mock function similar to what we'd use in production
            def get_config_class_from_registry(messagebus_type: str):
                registry_file = Path(os.environ.get("VOLTTRON_HOME", "~/.volttron")).expanduser() / "messagebus_registry.json"
                with open(registry_file) as f:
                    registry_data = json.load(f)
                
                class_path = registry_data.get(messagebus_type)
                if not class_path:
                    return None
                
                module_path, class_name = class_path.rsplit(".", 1)
                import importlib
                module = importlib.import_module(module_path)
                return getattr(module, class_name)
            
            # Test the registry lookup
            config_class = get_config_class_from_registry("fake")
            assert config_class == FakeMessageBusConfig
            
            # Test creating a config with the retrieved class
            options = {"instance_name": "registry-test"}
            config = config_class.create_from_options(options)
            assert config.instance_name == "registry-test"
            assert config.test_mode is True  # From defaults
            
        finally:
            if original_home:
                os.environ["VOLTTRON_HOME"] = original_home
            else:
                os.environ.pop("VOLTTRON_HOME", None)