#!/usr/bin/env bash
# exit on error
set -o errexit

# Install system dependencies
apt-get update -y
apt-get install -y build-essential python3-dev

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
pip install -r requirements.txt 