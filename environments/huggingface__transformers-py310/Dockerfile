ARG PYTHON_IMAGE=python:3.10-slim-bookworm
FROM ${PYTHON_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

COPY apt-packages.txt /tmp/apt-packages.txt

RUN apt-get update && \
    grep -vE '^\s*#|^\s*$' /tmp/apt-packages.txt | \
    xargs apt-get install -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade \
    pip==24.0 \
    setuptools==69.5.1 \
    wheel==0.43.0

COPY requirements-lock.txt /tmp/requirements-lock.txt

RUN python -m pip install \
    --no-cache-dir \
    -r /tmp/requirements-lock.txt

WORKDIR /repo

CMD ["/bin/bash"]
