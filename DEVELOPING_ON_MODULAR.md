# Developing on Modular Volttron


The following documentation steps through the process of setting up your environment to start
developing on modular VOLTTRON.

There are requirements in order to follow this README. The following requirements should be installed system-wide, 
so they are available to be used throughout the README.

* Poetry 1.2.2

## Installing poetry
See [poetry installation](https://github.com/eclipse-volttron/volttron-core/tree/develop#poetry)


# Development

##  New Agent 
* Please use the tool [copier-poetry-volttron-agent](https://github.com/VOLTTRON/copier-poetry-volttron-agent/tree/develop) to create a new agent. 

## Existing Agent
* Fork the Agent repo on Github
* Clone the repo in your local environment
* Setup the environment using poetry

```shell
poetry install 
```

* Create a working branch off of 'develop'
* Make a code change
* Run tests

```shell
poetry run pytest tests/
```
* Create a Pull Request (PR)
  * Please see the [contributing.md](CONTRIBUTING.md) document before contributing to this repo.
  * Go on your forked Github repo and create a PR.  

## Building a Wheel

To build a wheel from this project, execute the following command at the root level of this repo:

```shell
poetry build
```

The wheel and source distribution will be located in the ```./dist/``` directory.

## Bumping version number of project

To bump the version number of the project execute one of the following.

```shell
# patch, minor, major, prepatch, preminor, premajor, prerelease

# use patch
user@path$ poetry patch

# output
Bumping version from 0.2.0-alpha.0 to 0.2.0

# use prepatch
user@path$ poetry version prepatch

# output
Bumping version from 0.2.0 to 0.2.1-alpha.0


## Testing

To write tests, install [`volttron-testing`](https://github.com/eclipse-volttron/volttron-testing/tree/develop) as a 
dev dependency. Use poetry to install `volttron-testing` into your environment:

```shell
poetry add volttron-testing
```

`volttron-testing` offers several tools that you can use to write tests. 

## Tests

### Unit Tests

Use `TestServer` to create the testing environment for unit tests. For an example of a unit test, 
see the unit tests created for [volttron-listener](https://github.com/eclipse-volttron/volttron-listener/blob/develop/tests/test_agent_workings.py)


### Integration Tests

Use `PlatformWrapper` to create the testing environment for integration tests. For an example of an integration test, 
see the integration tests created for [volttron-listener](https://github.com/eclipse-volttron/volttron-listener/blob/develop/tests/test_integration.py)
