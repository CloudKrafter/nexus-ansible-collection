#!/bin/bash

# Get python version
python_version=$(python --version | cut -d " " -f 2)

# set python_version variable system-wide
echo "export python_version=$python_version" >> /etc/profile

# Create and activate a Python virtual environment
echo "Creating UV virtual environment for Python $python_version"
curl -LsSf https://astral.sh/uv/install.sh | sh
echo 'eval "$(uv generate-shell-completion bash)"' >> ~/.bashrc
source ~/.bashrc
uv sync --frozen
