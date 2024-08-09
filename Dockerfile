FROM immauss/openvas

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

COPY scripts/* /scripts/

RUN apt-get update && apt-get install -y virtualenv
COPY req.txt /req.txt
RUN python3.11 -m virtualenv -p python3.11 /venv
RUN /venv/bin/python3.11 -m pip install --upgrade pip
RUN /venv/bin/python3.11 -m pip install -r /req.txt
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
WORKDIR /app

RUN chmod +x /scripts/start.sh

ENTRYPOINT ["/bin/sh", "-c", "/usr/bin/sh /scripts/start.sh & /venv/bin/python3.11 /app/agent/main.py"]
