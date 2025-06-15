import json
import importlib
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from volttron.types import MessageBusConfig
from volttron_core_fixtures.fake_messagebus import FakeMessageBusConfig, FakeMessageBus

class TestMessageBusIntegration:
    """Integration tests for messagebus registration system"""
    
    def test_end_to_end_third_party_registration(self, create_volttron_home_fun_scope):
        """Test complete flow using existing volttron_home fixture"""
        volttron_home = Path(create_volttron_home_fun_scope)
        
        # Setup: Create registry as if third-party installed it
        registry_data = {
            "fake": "volttron_core_fixtures.fake_messagebus.FakeMessageBusConfig"
        }
        registry_file = volttron_home / "messagebus_registry.json"
        with open(registry_file, 'w') as f:
            json.dump(registry_data, f)
        
        # Load the config class
        with open(registry_file) as f:
            registry = json.load(f)
        
        class_path = registry["fake"]
        module_path, class_name = class_path.rsplit(".", 1)
        module = importlib.import_module(module_path)
        ConfigClass = getattr(module, class_name)
        
        # Verify it properly extends the base MessageBusConfig
        assert issubclass(ConfigClass, MessageBusConfig)
        
        # Create config with options
        options = {
            "instance_name": "integration-test",
            "test_mode": False,
            "connection_timeout": 60
        }
        config = ConfigClass.create_from_options(options)
        
        # Verify configuration
        assert config.instance_name == "integration-test"
        assert config.test_mode is False
        assert config.connection_timeout == 60
        
        # Create and test messagebus
        message_bus = FakeMessageBus(config)
        assert not message_bus.is_running()
        
        message_bus.start()
        assert message_bus.is_running()
        
        message_bus.stop()
        assert not message_bus.is_running()
    
    def test_config_store_integration(self, create_volttron_home_fun_scope):
        """Test integration with VOLTTRON's config storage system"""
        volttron_home = create_volttron_home_fun_scope
        
        # Mock the ClientContext to return our test volttron_home
        with patch('volttron.utils.context.ClientContext.get_volttron_home') as mock_get_home:
            mock_get_home.return_value = volttron_home
            
            from volttron.utils import store_message_bus_config
            store_message_bus_config("fake", "test-instance")
            
            # Verify config was stored correctly
            config_file = Path(volttron_home) / "config"
            assert config_file.exists()
            
            from configparser import ConfigParser
            config = ConfigParser()
            config.read(config_file)
            
            assert config.get("volttron", "messagebus") == "fake"
            assert config.get("volttron", "instance-name") == "test-instance"
    
    def test_messagebus_resolution_with_service_repo(self, create_volttron_home_fun_scope):
        """Test how messagebus gets resolved in the actual platform"""
        volttron_home = Path(create_volttron_home_fun_scope)
        
        # Setup registry
        registry_data = {
            "fake": "volttron_core_fixtures.fake_messagebus.FakeMessageBusConfig"
        }
        registry_file = volttron_home / "messagebus_registry.json"
        with open(registry_file, 'w') as f:
            json.dump(registry_data, f)
        
        # Mock ClientContext for the store operation
        with patch('volttron.utils.context.ClientContext.get_volttron_home') as mock_get_home:
            mock_get_home.return_value = str(volttron_home)
            
            # First store a config
            from volttron.utils import store_message_bus_config
            store_message_bus_config("fake", "platform-test")
        
        # This simulates what happens in platform startup
        def resolve_messagebus_from_config():
            config_file = volttron_home / "config"
            if config_file.exists():
                from configparser import ConfigParser
                config = ConfigParser()
                config.read(config_file)
                
                if config.has_option("volttron", "messagebus"):
                    messagebus_type = config.get("volttron", "messagebus")
                    instance_name = config.get("volttron", "instance-name")
                    
                    # Load from registry
                    with open(registry_file) as f:
                        registry = json.load(f)
                    
                    class_path = registry[messagebus_type]
                    module_path, class_name = class_path.rsplit(".", 1)
                    module = importlib.import_module(module_path)
                    config_class = getattr(module, class_name)
                    
                    # Create config
                    options = {"instance_name": instance_name}
                    return config_class.create_from_options(options)
            return None
        
        # Then resolve it
        messagebus_config = resolve_messagebus_from_config()
        
        assert messagebus_config is not None
        assert isinstance(messagebus_config, FakeMessageBusConfig)
        assert messagebus_config.instance_name == "platform-test"