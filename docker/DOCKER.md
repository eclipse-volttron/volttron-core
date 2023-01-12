# VOLTTRON Docker Image

This is the readme for the VOLTTRON docker image. 


## Minimal Execution

A volttron is able to be executed directly from docker.  This will create a running volttron, but will not
persist after the container stops.

```bash
# Starts a volttron in the background
docker run -d --name volttron --rm -it eclipsevolttron/volttron:v10
```

```bash
docker logs volttron
```

```bash
# run a single command from the command line
docker exec --user volttron -it volttron vctl status
```

```bash
# creates a bash shell inside the container.
docker exec --user volttron -it volttron bash

vctl status

vctl install volttron-listener

vctl status

vctl shutdown --platform
```

## Persisting the VOLTTRON data 

```bash
# Allow the datavolume (contains VOLTTRON_HOME and virtual environment) to
# be persisted to the host.
docker run -d -v $PWD/datavolume:/home/volttron/datavolume \
    --name volttron --rm -it eclipsevolttron/volttron:v10
```

## Initialization of Platform

```bash
# Starts a volttron persisting volttron home.
docker run -d -v $PWD/example/config:/config \
    -v $PWD/datavolume:/home/volttron/datavolume \
    -e 'PLATFORM_CONFIG=/config/example_platform_config.yml' \
    --name volttron --rm -it eclipsevolttron/volttron:v10
```
