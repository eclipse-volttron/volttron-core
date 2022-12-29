
# bullseye's default python
FROM python:3.10-slim-bullseye

SHELL [ "bash", "-c" ]

RUN apt-get update && apt-get install -y \
    build-essential \
    openssl \ 
    libssl-dev \
    libevent-dev

RUN adduser --disabled-password --gecos "" volttron
ENV VOLTTRON_HOME=/home/volttron/.volttron

USER volttron
WORKDIR /home/volttron

VOLUME $VOLTTRON_HOME
RUN mkdir $VOLTTRON_HOME

# install minimal volttron
RUN pip install volttron

ENV PATH="/home/volttron/.local/bin:${PATH}"
USER root
COPY startup /startup
RUN chown volttron:volttron /startup
ENTRYPOINT ["/bin/sh", "/startup/entrypoint.sh"]
CMD volttron -vv