#!/bin/bash

set -eux

if [ ! -d $VOLTTRON_HOME ]
then
    mkdir -p $VOLTTRON_HOME
fi

if [ ! -d $VOLTTRON_AGENT_ENV ]
then
    mkdir -p $VOLTTRON_AGENT_ENV
fi

chown -R volttron:volttron $VOLTTRON_DATA_VOLUME

if [ -d "/config" ]
then
    if [ ! -f "$VOLTTRON_HOME/initialized" ]
    then
        # chown -R volttron.volttron /config
        chown -R volttron.volttron /startup
        exec runuser -u volttron python /startup/setup-platform.py
        #exec runuser -u volttron -- "python /startup/setup-platform.py"
    fi
fi



exec runuser -u volttron -- "$@"