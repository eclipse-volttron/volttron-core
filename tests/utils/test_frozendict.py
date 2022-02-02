from _pytest._code.code import ExceptionInfo
import pytest

from volttron.utils.frozendict import FrozenDict


def test_frozen_dict():
    fd = FrozenDict()
    fd.freeze()

    with pytest.raises(TypeError) as ex:
        fd["foo"] = "bar"

    assert "foo" not in fd.keys()
    assert "Attempted assignment to a frozen dict" == ex.value.args[0]

    # TODO handle htis case.
    # fd.update({"alpha": "beta"})

    # print(list(fd.keys()))
    # assert 1 == len(list(fd.keys()))

    # assert 'alpha' not in list(fd.keys())
    # assert 'foo' in list(fd.keys())
