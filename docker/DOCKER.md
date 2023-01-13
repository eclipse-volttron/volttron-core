# VOLTTRON Docker Image

This is the readme for the VOLTTRON docker image.  The readme gives commands for starting a minimal volttron
environment (one without any agents) through to initializing the full environment using custom configuration and
datavolumes.

Note: it is assumed the commands below are executing in the ```docker``` directory of volttron-core repository.


## Minimal Execution

A volttron is able to be executed directly from docker.  This will create a running volttron, but will not
persist on the host after the container stops.

```bash
# Starts a volttron in the background
docker run -d --name volttron --rm -it eclipsevolttron/volttron:v10
```

```bash
# View the logs add --follow to keep the logs outputing.
docker logs volttron
```

```bash
# run a single volttron command from the command line
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

Creating a datavolume allows a container to maintain its state over restarting.  The
volttron container stores it's state in a directory /home/volttron/datavolume.  

This first command will create a directory on the host called $PWD/datavolume (if it doesn't exist)
and will use it for maintaining a VOLTTRON_HOME and a virtual environment that is used inside the container.

```bash
# Allow the datavolume (contains VOLTTRON_HOME and virtual environment) to
# be persisted to the host.
docker run -d -v $PWD/datavolume:/home/volttron/datavolume \
    --name volttron --rm -it eclipsevolttron/volttron:v10
```

## Initialization of Platform

Initialization of the platform requires getting information to the docker container so that the
volttron can be created.  To do this a second mount point is specified using the flags ```-v $PWD/example/config:/config```.
This will mount the contents on the host at $PWD/examples/config to the point inside the container /config.  The 
environmental variable ```-e 'PLATFORM_CONFIG=/config/example_platform_config.yml'``` informs the volttron container where its configuration file for the platform is located.  Note that this is from the containers perspective not the host.

```bash
# Starts a volttron persisting volttron home.
docker run -d -v $PWD/example/config:/config \
    -v $PWD/datavolume:/home/volttron/datavolume \
    -e 'PLATFORM_CONFIG=/config/example_platform_config.yml' \
    --name volttron --rm -it eclipsevolttron/volttron:v10
```

Once executing the above command monitor the logs via ```docker logs volttron``` or through another monitoring tool such as docker desktop or podman.

