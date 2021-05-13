FROM ubuntu:18.04

RUN apt-get -q update

RUN apt-get install -y python3-pip

ARG GRAPH_USER=graph
ARG GRAPH_HOME=/home/graph

RUN useradd -m -d "${GRAPH_HOME}" -s /bin/bash "${GRAPH_USER}"

ADD check_poi.py "${GRAPH_HOME}/check_poi.py"

RUN chmod +x "${GRAPH_HOME}/check_poi.py"
RUN chown $GRAPH_USER:$GRAPH_USER "${GRAPH_HOME}/check_poi.py"

USER $GRAPH_USER
WORKDIR $GRAPH_HOME

COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt

ENTRYPOINT [ "cat" ]
