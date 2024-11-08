FROM python:3.12-bullseye

RUN addgroup --system netdev && useradd -m --shell /bin/bash -G netdev appuser && echo "appuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

WORKDIR /usr/src/app

COPY device-discovery/ ./device-discovery

RUN pip install --no-cache-dir ./device-discovery/

RUN rm -rf ./device-discovery

USER appuser

CMD [ "device-discovery" ]