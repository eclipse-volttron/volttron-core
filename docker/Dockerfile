
# bullseye's default python
FROM python:3.10-slim-bullseye

SHELL [ "bash", "-c" ]

RUN apt-get update && apt-get install -y \
    build-essential \
    openssl \ 
    libssl-dev \
    libevent-dev 
    
RUN pip install PyYaml
    #pip install PyYaml

RUN adduser --disabled-password --gecos "" volttron
ENV VOLTTRON_DATA_VOLUME=/home/volttron/datavolume
ENV VOLTTRON_HOME=${VOLTTRON_DATA_VOLUME}/volttron_home
ENV VOLTTRON_VENV=${VOLTTRON_DATA_VOLUME}/venv
ENV PIP_CACHE_DIR=${VOLTTRON_DATA_VOLUME}/cache

USER volttron
WORKDIR /home/volttron

VOLUME $VOLTTRON_DATA_VOLUME
RUN mkdir -p $VOLTTRON_HOME && \
    mkdir -p $VOLTTRON_VENV && \
    mkdir -p $PIP_CACHE_DIR && \
    mkdir -p /home/volttron/.local && \
    mkdir -p /home/volttron/.config/pip

ENV PATH="${VOLTTRON_VENV}/bin:${PATH}"
USER root
COPY startup /startup
RUN mv /startup/pip.conf /home/volttron/.config/pip
RUN chown volttron:volttron /startup
ENTRYPOINT ["/bin/bash", "/startup/entrypoint.sh"]
