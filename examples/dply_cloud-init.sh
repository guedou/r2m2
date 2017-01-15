#!/bin/bash
# Copyright (C) 2017 Guillaume Valadon <guillaume@valadon.net>

# r2m2 install script for Unbuntu based free https://dply.co/ VM

# Install packages
apt-get update
apt-get install -y docker.io

# Pull r2m2 Docker image
docker pull guedou/r2m2
