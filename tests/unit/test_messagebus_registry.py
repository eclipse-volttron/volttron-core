import json
import tempfile
import importlib
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from volttron.types import MessageBusConfig

class TestMessageBusRegistry:
    """Test the messagebus registration and loading system"""
    
    def test_registry_file_creation(self, tmp_path):
        """Test creating a messagebus registry file"""
        registry_data = {
            "fake": "volttron_core_fixtures.fake_messagebus.FakeMessageBusConfig",
            "custom": "some.external.package.CustomMessageBusConfig"
        }
        
        registry_file = tmp_path / "messagebus_registry.json"
        with open(registry_file, 'w') as f:
            json.dump(registry_data, f)
        
        # Verify file was created correctly
        with open(registry_file) as f:
            loaded = json.load(f)
        
        assert loaded == registry_data
    
    def test_config_class_loading_success(self):
        """Test successful loading of a config class from registry"""
        class_path = "volttron_core_fixtures.fake_messagebus.FakeMessageBusConfig"
        
        module_path, class_name = class_path.rsplit(".", 1)
        module = importlib.import_module(module_path)
        config_class = getattr(module, class_name)
        
        # Verify it's a proper MessageBusConfig subclass
        assert issubclass(config_class, MessageBusConfig)
        assert hasattr(config_class, 'get_defaults')
        assert callable(config_class.get_defaults)
    
    def test_config_class_loading_module_not_found(self):
        """Test handling of missing module"""
        class_path = "nonexistent.module.ConfigClass"
        
        module_path, class_name = class_path.rsplit(".", 1)
        
        with pytest.raises(ImportError):
            importlib.import_module(module_path)
    
    def test_config_class_loading_class_not_found(self):
        """Test handling of missing class in existing module"""
        class_path = "volttron_core_fixtures.fake_messagebus.NonExistentClass"
        
        module_path, class_name = class_path.rsplit(".", 1)
        module = importlib.import_module(module_path)
        
        with pytest.raises(AttributeError):
            getattr(module, class_name)
    
    def test_registry_lookup_function(self, tmp_path):
        """Test the registry lookup functionality"""
        def get_config_class_from_registry(messagebus_type: str, registry_path: Path):
            """Helper function to load config class from registry"""
            try:
                with open(registry_path) as f:
                    registry_data = json.load(f)
                
                class_path = registry_data.get(messagebus_type)
                if not class_path:
                    return None
                
                module_path, class_name = class_path.rsplit(".", 1)
                module = importlib.import_module(module_path)
                return getattr(module, class_name)
            except (FileNotFoundError, json.JSONDecodeError, ImportError, AttributeError):
                return None
        
        # Create test registry
        registry_data = {
            "fake": "volttron_core_fixtures.fake_messagebus.FakeMessageBusConfig"
        }
        registry_file = tmp_path / "messagebus_registry.json"
        with open(registry_file, 'w') as f:
            json.dump(registry_data, f)
        
        # Test successful lookup
        config_class = get_config_class_from_registry("fake", registry_file)
        assert config_class is not None
        assert issubclass(config_class, MessageBusConfig)
        
        # Test missing type
        config_class = get_config_class_from_registry("nonexistent", registry_file)
        assert config_class is None
        
        # Test missing file
        missing_file = tmp_path / "missing.json"
        config_class = get_config_class_from_registry("fake", missing_file)
        assert config_class is None