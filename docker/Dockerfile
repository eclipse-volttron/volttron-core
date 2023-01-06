
# bullseye's default python
FROM python:3.10-slim-bullseye

SHELL [ "bash", "-c" ]

RUN apt-get update && apt-get install -y \
    build-essential \
    openssl \ 
    libssl-dev \
    libevent-dev

RUN adduser --disabled-password --gecos "" volttron
ENV VOLTTRON_DATA_VOLUME=/home/volttron/datavolume
ENV VOLTTRON_HOME=${VOLTTRON_DATA_VOLUME}/.volttron
ENV VOLTTRON_AGENT_ENV=${VOLTTRON_DATA_VOLUME}/venv

USER volttron
WORKDIR /home/volttron

VOLUME $VOLTTRON_HOME
RUN mkdir -p $VOLTTRON_HOME
RUN mkdir -p VOLTTRON_AGENT_ENV

VOLUME /home/volttron/.local
RUN mkdir -p /home/volttron/.local

# install minimal volttron
RUN pip install volttron==10.0.3a0

RUN mkdir -p /home/volttron/.config/pip

ENV PATH="/home/volttron/datavolume/venv:/home/volttron/.local/bin:${PATH}"
USER root
COPY startup /startup
RUN chown volttron:volttron /startup
RUN cp /startup/pip.conf /home/volttron/.config/pip
ENTRYPOINT ["/bin/sh", "/startup/entrypoint.sh"]
CMD volttron -vv