[![Pytests](https://github.com/VOLTTRON/volttron-core/actions/workflows/run-tests.yml/badge.svg)](https://github.com/VOLTTRON/volttron-core/actions/workflows/run-tests.yml)

## Environment setup

Note: This repo uses [Poetry](https://python-poetry.org/), a dependency management and packaging tool for Python. If you don't have Poetry installed on your machine, follow [these steps](https://python-poetry.org/docs/#installation) to install it on your machine.
To check if Poetry is installed, run `poetry --version`. If you receive the error 'command not found: poetry', add the following line to your '~/.bashrc' script: ```export PATH=$PATH:$HOME/.poetry/bin```.

1. Create virtual environment

By default, poetry creates a virtual environment in {cache-dir}/virtualenvs
({cache-dir}\virtualenvs on Windows). To configure 'poetry' to create the virtualenv inside this project's root
directory, run the following command:

[```poetry config virtualenvs.in-project true```](https://python-poetry.org/docs/configuration
)

Then to create the virtual environment, run the following command:

```shell
poetry shell
```

## Install
Run the following commands to install volttron -  
```
poetry update
poetry install
```

## Running volttron and volttron-ctl 

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
