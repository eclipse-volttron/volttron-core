import pytest
from volttron.utils import load_config


def test_load_config_json():
    with pytest.raises(ValueError):
        load_config(None)


def test_raise_exception_no_file():

    with pytest.raises(ValueError):
        load_config("")
