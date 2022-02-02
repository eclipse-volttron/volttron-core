import os
import shutil
import sys
import tempfile

import pytest

# add
from volttron.utils import ClientContext

if "volttron" not in sys.path:
    sys.path.insert(0, "volttron")


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
    # default permissions for folders under /tmp directory doesn't not have read or execute for group or others
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
