# tests/integration/test_global_messagebus_integration.py
import json
import os
from pathlib import Path
from unittest.mock import patch

from volttron.types.messagebus import get_messagebus_config_class
from volttron_core_fixtures.fake_messagebus import FakeMessageBusConfig, FakeMessageBus

class TestGlobalMessageBusIntegration:
    """Integration tests for global messagebus registry system"""
    
    def test_end_to_end_system_registry(self, tmp_path):
        """Test complete flow using system-wide registry"""
        # Setup system registry
        fake_home = tmp_path / "fake_home"
        registry_dir = fake_home / ".local" / "share" / "volttron"
        registry_dir.mkdir(parents=True)
        
        registry_data = {
            "fake": "volttron_core_fixtures.fake_messagebus.FakeMessageBusConfig"
        }
        
        registry_file = registry_dir / "messagebus_registry.json"
        with open(registry_file, 'w') as f:
            json.dump(registry_data, f)
        
        # Test using the global registry functions
        with patch('pathlib.Path.home', return_value=fake_home):
            with patch.dict(os.environ, {}, clear=True):
                # Load config class via global registry
                ConfigClass = get_messagebus_config_class("fake")
                
                assert ConfigClass is not None
                assert ConfigClass == FakeMessageBusConfig
                
                # Create and test configuration
                options = {
                    "instance_name": "system-registry-test",
                    "test_mode": False
                }
                config = ConfigClass.create_from_options(options)
                
                assert config.instance_name == "system-registry-test"
                assert config.test_mode is False
                
                # Create and test messagebus
                message_bus = FakeMessageBus(config)
                assert not message_bus.is_running()
                
                message_bus.start()
                assert message_bus.is_running()
                
                message_bus.stop()
                assert not message_bus.is_running()
    
    def test_platform_integration_with_global_registry(self, create_volttron_home_fun_scope, tmp_path):
        """Test integration with platform using global registry"""
        volttron_home = Path(create_volttron_home_fun_scope)
        fake_user_home = tmp_path / "user_home"
        
        # Setup system registry
        system_registry_dir = fake_user_home / ".local" / "share" / "volttron"
        system_registry_dir.mkdir(parents=True)
        
        system_registry_data = {
            "fake": "volttron_core_fixtures.fake_messagebus.FakeMessageBusConfig"
        }
        
        system_registry_file = system_registry_dir / "messagebus_registry.json"
        with open(system_registry_file, 'w') as f:
            json.dump(system_registry_data, f)
        
        # Test platform-style resolution
        def resolve_messagebus_for_platform(messagebus_type: str, instance_name: str):
            """Simulate how platform would resolve messagebus"""
            with patch('pathlib.Path.home', return_value=fake_user_home):
                with patch.dict(os.environ, {"VOLTTRON_HOME": str(volttron_home)}):
                    config_class = get_messagebus_config_class(messagebus_type)
                    
                    if config_class:
                        options = {"instance_name": instance_name}
                        return config_class.create_from_options(options)
                    return None
        
        # Test resolution
        config = resolve_messagebus_for_platform("fake", "platform-integration-test")
        
        assert config is not None
        assert isinstance(config, FakeMessageBusConfig)
        assert config.instance_name == "platform-integration-test"
        
        # Test messagebus creation
        message_bus = FakeMessageBus(config)
        assert not message_bus.is_running()
        
        message_bus.start()
        assert message_bus.is_running()
    
    def test_registry_precedence_integration(self, create_volttron_home_fun_scope, tmp_path):
        """Test that system registry takes precedence over instance registry"""
        volttron_home = Path(create_volttron_home_fun_scope)
        fake_user_home = tmp_path / "user_home"
        
        # Setup system registry
        system_registry_dir = fake_user_home / ".local" / "share" / "volttron"
        system_registry_dir.mkdir(parents=True)
        
        system_registry_data = {
            "fake": "volttron_core_fixtures.fake_messagebus.FakeMessageBusConfig"
        }
        
        system_registry_file = system_registry_dir / "messagebus_registry.json"
        with open(system_registry_file, 'w') as f:
            json.dump(system_registry_data, f)
        
        # Setup instance registry with different (invalid) entry
        instance_registry_data = {
            "fake": "should.not.be.used.InvalidClass"
        }
        
        instance_registry_file = volttron_home / "messagebus_registry.json"
        with open(instance_registry_file, 'w') as f:
            json.dump(instance_registry_data, f)
        
        # Test - should use system registry
        with patch('pathlib.Path.home', return_value=fake_user_home):
            with patch.dict(os.environ, {"VOLTTRON_HOME": str(volttron_home)}):
                config_class = get_messagebus_config_class("fake")
        
        # Should get FakeMessageBusConfig from system registry
        # not try to load the invalid class from instance registry
        assert config_class == FakeMessageBusConfig