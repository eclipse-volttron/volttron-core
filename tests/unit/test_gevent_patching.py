"""Importing volttron.client patches subprocess along with os.

gevent 25.8.1 and later close pipe ends through the hub once os is patched. An unpatched subprocess.Popen then
blocks reading its error pipe, waiting for a close that the blocked hub never performs, so every subprocess call
from the server hung (agent installs timed out after 'poetry add'). Each check runs in a fresh interpreter so
the patch state of this test process does not matter.
"""
import subprocess
import sys

import pytest

CHECK = r"""
import sys
import volttron.client    # applies VOLTTRON's gevent patches
from gevent import monkey
import gevent, subprocess
assert monkey.is_module_patched("os") and monkey.is_module_patched("subprocess"), "subprocess not patched"
def child():
    return subprocess.run([sys.executable, "-c", "pass"], capture_output=True).returncode
ticker = gevent.spawn(lambda: [gevent.sleep(0.05) for _ in iter(int, 1)])    # keep the hub busy, as a server does
with gevent.Timeout(20):
    assert gevent.spawn(child).get() == 0
ticker.kill()
print("ok")
"""


def test_subprocess_is_patched_and_runs_inside_a_greenlet():
    result = subprocess.run([sys.executable, "-c", CHECK], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0 and result.stdout.strip().endswith("ok"), result.stderr[-2000:]
