import os
import shutil
import tempfile
from pathlib import Path
import pytest
from typing import Optional, Generator, Union


@pytest.fixture
def volttron_home() -> Generator[Path, None, None]:
    """
    Create a temporary VOLTTRON_HOME directory and set it as an environment variable.
    
    This fixture creates a clean, isolated directory for each test that uses it,
    and automatically cleans it up afterward.
    
    Returns:
        Path: Path to the temporary VOLTTRON_HOME directory
    """
    # Save original environment
    original_home = os.environ.get("VOLTTRON_HOME")
    
    try:
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp(prefix="volttron_home_")
        temp_path = Path(temp_dir)
        
        # Create standard subdirectories
        (temp_path / "agents").mkdir()
        (temp_path / "certificates").mkdir()
        (temp_path / "run").mkdir()
        (temp_path / "ssh").mkdir()
        (temp_path / "keystores").mkdir()
        
        # Set the environment variable - never use default
        os.environ["VOLTTRON_HOME"] = str(temp_path)
        
        # Yield the path for the test to use
        yield temp_path
        
    finally:
        # Always restore original environment, even if test fails
        if original_home is not None:
            os.environ["VOLTTRON_HOME"] = original_home
        else:
            os.environ.pop("VOLTTRON_HOME", None)
        
        # Clean up the temporary directory
        if "temp_dir" in locals():
            shutil.rmtree(temp_dir)


@pytest.fixture
def isolated_volttron_home(request) -> Generator[Path, None, None]:
    """
    Create a test-specific VOLTTRON_HOME directory with the test name encoded.
    
    This creates a persistent directory that includes the test name, useful for
    debugging tests that fail or for running specific tests with preserved state.
    
    Returns:
        Path: Path to the VOLTTRON_HOME directory
    """
    # Save original environment
    original_home = os.environ.get("VOLTTRON_HOME")
    
    try:
        # Create a test-specific directory name
        test_name = request.node.name.replace("[", "_").replace("]", "_").replace("/", "_")
        test_dir = Path(tempfile.gettempdir()) / f"volttron_home_{test_name}"
        test_dir.mkdir(exist_ok=True, parents=True)
        
        # Create standard subdirectories
        (test_dir / "agents").mkdir(exist_ok=True)
        (test_dir / "certificates").mkdir(exist_ok=True)
        (test_dir / "run").mkdir(exist_ok=True)
        (test_dir / "ssh").mkdir(exist_ok=True)
        (test_dir / "keystores").mkdir(exist_ok=True)
        
        # Set the environment variable - never use default
        os.environ["VOLTTRON_HOME"] = str(test_dir)
        
        # Yield the path for the test to use
        yield test_dir
        
    finally:
        # Always restore original environment, even if test fails
        if original_home is not None:
            os.environ["VOLTTRON_HOME"] = original_home
        else:
            os.environ.pop("VOLTTRON_HOME", None)


@pytest.fixture
def persistent_volttron_home(request) -> Generator[Path, None, None]:
    """
    Create a persistent VOLTTRON_HOME that remains after tests for debugging purposes.
    
    This fixture creates a VOLTTRON_HOME directory that is not automatically cleaned up,
    which can be helpful for debugging failing tests.
    
    Returns:
        Path: Path to the persistent VOLTTRON_HOME directory
    """
    # Save original environment
    original_home = os.environ.get("VOLTTRON_HOME")
    
    try:
        # Create a directory with the test module name
        module_name = request.module.__name__.replace(".", "_")
        persistent_dir = Path(tempfile.gettempdir()) / f"volttron_persistent_{module_name}"
        persistent_dir.mkdir(exist_ok=True, parents=True)
        
        # Create standard subdirectories
        (persistent_dir / "agents").mkdir(exist_ok=True)
        (persistent_dir / "certificates").mkdir(exist_ok=True)
        (persistent_dir / "run").mkdir(exist_ok=True)
        (persistent_dir / "ssh").mkdir(exist_ok=True)
        (persistent_dir / "keystores").mkdir(exist_ok=True)
        
        # Set the environment variable - never use default
        os.environ["VOLTTRON_HOME"] = str(persistent_dir)
        
        # Print information for debugging purposes
        print(f"\nCreated persistent VOLTTRON_HOME at: {persistent_dir}\n")
        
        # Yield the path for the test to use
        yield persistent_dir
        
    finally:
        # Always restore original environment, even if test fails
        if original_home is not None:
            os.environ["VOLTTRON_HOME"] = original_home
        else:
            os.environ.pop("VOLTTRON_HOME", None)


def create_volttron_home_with_config(config_dict: Optional[dict] = None) -> Path:
    """
    Create a VOLTTRON_HOME directory with an optional config file.
    
    Args:
        config_dict: Dictionary of configuration values to write to config file
        
    Returns:
        Path: Path to the created VOLTTRON_HOME
    """
    import json
    
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix="volttron_home_")
    temp_path = Path(temp_dir)
    
    # Create standard subdirectories
    (temp_path / "agents").mkdir()
    (temp_path / "certificates").mkdir()
    (temp_path / "run").mkdir()
    (temp_path / "ssh").mkdir()
    (temp_path / "keystores").mkdir()
    
    # Write config file if provided
    if config_dict:
        with open(temp_path / "config", "w") as f:
            json.dump(config_dict, f, indent=2)
    
    return temp_path


@pytest.fixture
def configured_volttron_home(request) -> Generator[Path, None, None]:
    """
    Create a VOLTTRON_HOME with configuration from a pytest parameter.
    
    Use with @pytest.mark.parametrize to test different configurations:
    
    @pytest.mark.parametrize("configured_volttron_home", 
                           [{"message_bus": "zmq"}, {"message_bus": "rmq"}], 
                           indirect=True)
    def test_with_different_configs(configured_volttron_home):
        ...
    
    Returns:
        Path: Path to the configured VOLTTRON_HOME
    """
    # Save original environment
    original_home = os.environ.get("VOLTTRON_HOME")
    
    try:
        # Get configuration from parameter or use empty dict
        config_dict = getattr(request, "param", {})
        
        # Create the directory with config
        temp_path = create_volttron_home_with_config(config_dict)
        
        # Set the environment variable - never use default
        os.environ["VOLTTRON_HOME"] = str(temp_path)
        
        # Yield the path for the test to use
        yield temp_path
        
    finally:
        # Always restore original environment, even if test fails
        if original_home is not None:
            os.environ["VOLTTRON_HOME"] = original_home
        else:
            os.environ.pop("VOLTTRON_HOME", None)
        
        # Clean up
        if "temp_path" in locals():
            shutil.rmtree(temp_path)

def create_volttron_home(monkeypatch) -> str:
    """
    Creates a VOLTTRON_HOME temp directory for use within a testing context.
    This function will return a string containing the VOLTTRON_HOME but will not
    set the global variable.
    :return: str: the temp directory
    """
    volttron_home = tempfile.mkdtemp(prefix="/tmp/volttron_testing").strip()
    monkeypatch.setenv("VOLTTRON_HOME", volttron_home)

    # This is needed to run tests with volttron's secure mode. Without this
    # default permissions for folders under /tmp directory doesn't not have read or execute for
    # group or others
    os.chmod(volttron_home, 0o755)

    # Move volttron_home to be one level below the mkdir so that
    # the volttron.log file is not part of the same folder for
    # observer.
    volttron_home = os.path.join(volttron_home, "volttron_home")
    os.makedirs(volttron_home)

    return volttron_home


@pytest.fixture(scope="function")
def create_volttron_home_fun_scope(monkeypatch):

    volttron_home = create_volttron_home(monkeypatch)

    yield volttron_home.strip()

    shutil.rmtree(volttron_home, ignore_errors=True)


@pytest.fixture(scope="module")
def create_volttron_home_mod_scope(monkeypatch):

    volttron_home = create_volttron_home(monkeypatch)

    yield volttron_home.strip()

    shutil.rmtree(volttron_home, ignore_errors=True)