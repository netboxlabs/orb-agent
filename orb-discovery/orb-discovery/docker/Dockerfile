FROM python:3.12-bullseye

RUN addgroup --system netdev && useradd -m --shell /bin/bash -G netdev appuser && echo "appuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

WORKDIR /usr/src/app

COPY orb-discovery/ ./orb-discovery

RUN pip install --no-cache-dir ./orb-discovery/

RUN rm -rf ./orb-discovery

USER appuser

CMD [ "orb-discovery" ]