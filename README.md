[![Pytests](https://github.com/VOLTTRON/volttron-core/actions/workflows/run-tests.yml/badge.svg)](https://github.com/VOLTTRON/volttron-core/actions/workflows/run-tests.yml)

Run using commands

```commandline
# Can be run from ide
poetry run -m volttron.server -vv -l volttron.log &

# Running volttron-ctl
poetry run -m volttron.commands.control -vv status
```
