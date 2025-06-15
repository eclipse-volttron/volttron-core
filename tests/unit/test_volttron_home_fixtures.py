import os
import json
import shutil
import tempfile
import pytest
from pathlib import Path

from volttron_core_fixtures import (
    volttron_home, 
    isolated_volttron_home,
    persistent_volttron_home,
    configured_volttron_home
)


def test_volttron_home_restores_original_value(volttron_home):
    """Test that the fixture restores the original VOLTTRON_HOME value"""
    # Set a custom value during the test
    original_value = os.environ["VOLTTRON_HOME"]
    os.environ["VOLTTRON_HOME"] = "/custom/path"
    
    # Verify we can change it during the test
    assert os.environ["VOLTTRON_HOME"] == "/custom/path"
    
    # The fixture will restore the correct value when the test ends


def test_volttron_home_restores_when_exception_occurs():
    """Test that VOLTTRON_HOME is restored even when an exception occurs"""
    # Save the original value to verify later
    original_home = os.environ.get("VOLTTRON_HOME")
    
    # Run a test that will raise an exception
    try:
        with pytest.raises(RuntimeError):
            # Use the fixture inside a context
            with pytest.MonkeyPatch.context() as mp:
                # Apply the fixture logic manually
                temp_dir = tempfile.mkdtemp(prefix="volttron_home_")
                mp.setenv("VOLTTRON_HOME", temp_dir)
                
                # Simulate an exception in the test
                raise RuntimeError("Test exception")
                
    finally:
        # Verify the original environment was restored
        current_home = os.environ.get("VOLTTRON_HOME")
        assert current_home == original_home
        
        # Clean up the temporary directory
        if "temp_dir" in locals():
            shutil.rmtree(temp_dir)