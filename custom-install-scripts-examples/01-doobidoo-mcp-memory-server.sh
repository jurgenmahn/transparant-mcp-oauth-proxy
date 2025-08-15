#! /bin/bash

# cuda drivers
cd /tmp && \
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.0-1_all.deb
dpkg -i cuda-keyring_1.0-1_all.deb
apt-get update
wget http://security.ubuntu.com/ubuntu/pool/universe/n/ncurses/libtinfo5_6.3-2ubuntu0.1_amd64.deb
dpkg -i libtinfo5_6.3-2ubuntu0.1_amd64.deb
apt install -y --no-install-recommends cuda-toolkit-11-8 libcudnn8 libcublaslt12 libcublas12
