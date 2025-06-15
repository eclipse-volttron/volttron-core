import json
import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from volttron.types.messagebus import get_system_messagebus_registry, get_messagebus_config_class
from volttron.types import MessageBusConfig
from volttron_core_fixtures.fake_messagebus import FakeMessageBusConfig

class TestGlobalMessageBusRegistry:
    """Test the global messagebus registry system"""
    
    def test_get_system_messagebus_registry_xdg_config(self, tmp_path):
        """Test registry lookup using XDG_CONFIG_HOME"""
        # Setup fake XDG_CONFIG_HOME
        xdg_config = tmp_path / "xdg_config"
        xdg_config.mkdir()
        
        registry_dir = xdg_config / "volttron"
        registry_dir.mkdir()
        
        registry_data = {
            "fake": "volttron_core_fixtures.fake_messagebus.FakeMessageBusConfig",
            "zmq": "volttron.messagebus.zmq.ZMQMessageBusConfig"
        }
        
        registry_file = registry_dir / "messagebus_registry.json"
        with open(registry_file, 'w') as f:
            json.dump(registry_data, f)
        
        # Test with XDG_CONFIG_HOME set
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(xdg_config)}):
            result = get_system_messagebus_registry()
        
        assert result == registry_data
        assert "fake" in result
        assert "zmq" in result
    
    def test_get_system_messagebus_registry_home_fallback(self, tmp_path, monkeypatch):
        """Test registry lookup using ~/.local/share fallback"""
        # Mock Path.home() to return our tmp_path
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        
        registry_dir = fake_home / ".local" / "share" / "volttron"
        registry_dir.mkdir(parents=True)
        
        registry_data = {
            "rmq": "volttron.messagebus.rmq.RMQMessageBusConfig"
        }
        
        registry_file = registry_dir / "messagebus_registry.json"
        with open(registry_file, 'w') as f:
            json.dump(registry_data, f)
        
        # Mock Path.home() and ensure XDG_CONFIG_HOME is not set
        with patch('pathlib.Path.home', return_value=fake_home):
            with patch.dict(os.environ, {}, clear=True):
                result = get_system_messagebus_registry()
        
        assert result == registry_data
        assert "rmq" in result
    
    def test_get_system_messagebus_registry_missing_file(self):
        """Test behavior when registry file doesn't exist"""
        with patch('pathlib.Path.home') as mock_home:
            # Point to a non-existent location
            fake_home = Path("/nonexistent/path")
            mock_home.return_value = fake_home
            
            with patch.dict(os.environ, {}, clear=True):
                result = get_system_messagebus_registry()
        
        assert result == {}
    
    def test_get_system_messagebus_registry_corrupt_json(self, tmp_path, caplog):
        """Test handling of corrupted registry file"""
        registry_dir = tmp_path / ".local" / "share" / "volttron"
        registry_dir.mkdir(parents=True)
        
        # Create a corrupted JSON file
        registry_file = registry_dir / "messagebus_registry.json"
        with open(registry_file, 'w') as f:
            f.write("{ invalid json content")
        
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch.dict(os.environ, {}, clear=True):
                result = get_system_messagebus_registry()
        
        assert result == {}
        assert "Error reading messagebus registry" in caplog.text
    
    def test_get_messagebus_config_class_system_registry(self, tmp_path):
        """Test loading config class from system registry"""
        # Setup system registry
        registry_dir = tmp_path / ".local" / "share" / "volttron"
        registry_dir.mkdir(parents=True)
        
        registry_data = {
            "fake": "volttron_core_fixtures.fake_messagebus.FakeMessageBusConfig"
        }
        
        registry_file = registry_dir / "messagebus_registry.json"
        with open(registry_file, 'w') as f:
            json.dump(registry_data, f)
        
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch.dict(os.environ, {}, clear=True):
                config_class = get_messagebus_config_class("fake")
        
        assert config_class is not None
        assert config_class == FakeMessageBusConfig
        assert issubclass(config_class, MessageBusConfig)
    
    def test_get_messagebus_config_class_instance_registry_fallback(self, tmp_path):
        """Test fallback to instance-specific registry"""
        # Setup VOLTTRON_HOME registry (no system registry)
        volttron_home = tmp_path / "volttron_home"
        volttron_home.mkdir()
        
        registry_data = {
            "fake": "volttron_core_fixtures.fake_messagebus.FakeMessageBusConfig"
        }
        
        registry_file = volttron_home / "messagebus_registry.json"
        with open(registry_file, 'w') as f:
            json.dump(registry_data, f)
        
        # Mock empty system registry and set VOLTTRON_HOME
        with patch('volttron.types.messagebus.get_system_messagebus_registry', return_value={}):
            with patch.dict(os.environ, {"VOLTTRON_HOME": str(volttron_home)}):
                config_class = get_messagebus_config_class("fake")
        
        assert config_class is not None
        assert config_class == FakeMessageBusConfig
    
    def test_get_messagebus_config_class_system_priority(self, tmp_path):
        """Test that system registry has priority over instance registry"""
        # Setup system registry
        system_home = tmp_path / "system_home"
        system_registry_dir = system_home / ".local" / "share" / "volttron"
        system_registry_dir.mkdir(parents=True)
        
        system_registry_data = {
            "fake": "volttron_core_fixtures.fake_messagebus.FakeMessageBusConfig"
        }
        
        system_registry_file = system_registry_dir / "messagebus_registry.json"
        with open(system_registry_file, 'w') as f:
            json.dump(system_registry_data, f)
        
        # Setup instance registry with different class path
        volttron_home = tmp_path / "volttron_home"
        volttron_home.mkdir()
        
        instance_registry_data = {
            "fake": "some.other.class.path.ShouldNotBeUsed"
        }
        
        instance_registry_file = volttron_home / "messagebus_registry.json"
        with open(instance_registry_file, 'w') as f:
            json.dump(instance_registry_data, f)
        
        # Test - system registry should win
        with patch('pathlib.Path.home', return_value=system_home):
            with patch.dict(os.environ, {"VOLTTRON_HOME": str(volttron_home)}, clear=True):
                config_class = get_messagebus_config_class("fake")
        
        # Should get the class from system registry (FakeMessageBusConfig)
        # not the fake path from instance registry
        assert config_class == FakeMessageBusConfig
    
    def test_get_messagebus_config_class_not_found(self):
        """Test behavior when messagebus type is not found"""
        with patch('volttron.types.messagebus.get_system_messagebus_registry', return_value={}):
            with patch.dict(os.environ, {}, clear=True):
                config_class = get_messagebus_config_class("nonexistent")
        
        assert config_class is None
    
    def test_get_messagebus_config_class_import_error(self, tmp_path, caplog):
        """Test handling of import errors when loading config class"""
        registry_dir = tmp_path / ".local" / "share" / "volttron"
        registry_dir.mkdir(parents=True)
        
        # Registry with non-existent module
        registry_data = {
            "broken": "nonexistent.module.BrokenConfig"
        }
        
        registry_file = registry_dir / "messagebus_registry.json"
        with open(registry_file, 'w') as f:
            json.dump(registry_data, f)
        
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch.dict(os.environ, {}, clear=True):
                config_class = get_messagebus_config_class("broken")
        
        assert config_class is None
        assert "Error loading messagebus config class" in caplog.text
    
    def test_get_messagebus_config_class_attribute_error(self, tmp_path, caplog):
        """Test handling of missing class in existing module"""
        registry_dir = tmp_path / ".local" / "share" / "volttron"
        registry_dir.mkdir(parents=True)
        
        # Registry with existing module but non-existent class
        registry_data = {
            "broken": "volttron_core_fixtures.fake_messagebus.NonExistentClass"
        }
        
        registry_file = registry_dir / "messagebus_registry.json"
        with open(registry_file, 'w') as f:
            json.dump(registry_data, f)
        
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch.dict(os.environ, {}, clear=True):
                config_class = get_messagebus_config_class("broken")
        
        assert config_class is None
        assert "Error loading messagebus config class" in caplog.text