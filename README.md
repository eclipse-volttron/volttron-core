[![Pytests](https://github.com/VOLTTRON/volttron-core/actions/workflows/run-tests.yml/badge.svg)](https://github.com/VOLTTRON/volttron-core/actions/workflows/run-tests.yml)

Install:
Run the following commands to install volttron -  
```
poetry update
poetry install
```

Run using commands

```commandline
# Can be run from ide
poetry run python3 -m volttron.server -vv -l volttron.log &

# Running volttron-ctl
poetry run python3 -m volttron.commands.control -vv status
```
To run the above commands without the "poetry run" prefix run the commands within an activated environment. Run the command
```
poetry shell
```
to activate the venv
