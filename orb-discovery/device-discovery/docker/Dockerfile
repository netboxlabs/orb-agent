FROM python:3.12-slim-bullseye AS builder

WORKDIR /usr/src/app

COPY . .

RUN python -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install --no-cache-dir . && \
    deactivate

FROM python:3.12-slim-bullseye

RUN addgroup --system netdev && useradd -m --shell /bin/bash -G netdev appuser && echo "appuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

COPY --from=builder /opt/venv /opt/venv

# Activate virtual environment for all users
ENV PATH="/opt/venv/bin:$PATH"

USER appuser

CMD [ "device-discovery" ]