# Dockerfile
FROM mcr.microsoft.com/devcontainers/python:1-3.12-bullseye

# Install Python dependencies and Ansible Galaxy roles
COPY requirements.txt /tmp/
RUN pip install --upgrade pip setuptools && \
    pip install -r /tmp/requirements.txt && \
    rm -rf /tmp/requirements.txt

# Install Minio client
RUN curl https://dl.min.io/client/mc/release/linux-amd64/mc \
    --create-dirs \
    -o /usr/local/bin/mc && \
    chmod +x /usr/local/bin/mc

# Set up additional features and clean up in a single RUN command
RUN apt-get update && \
    apt-get install -y docker.io && \
    rm -rf /var/lib/apt/lists/*
