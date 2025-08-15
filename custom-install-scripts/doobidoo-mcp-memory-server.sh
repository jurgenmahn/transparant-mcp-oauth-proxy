#! /bin/bash

# cuda drivers
cd /tmp && \
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.0-1_all.deb
dpkg -i cuda-keyring_1.0-1_all.deb
apt-get update
wget http://security.ubuntu.com/ubuntu/pool/universe/n/ncurses/libtinfo5_6.3-2ubuntu0.1_amd64.deb
dpkg -i libtinfo5_6.3-2ubuntu0.1_amd64.deb
apt install -y --no-install-recommends cuda-toolkit-11-8 libcudnn8 libcublaslt12 libcublas12
 
mkdir -p /doobidoo-mcp-memory-server && cd /doobidoo-mcp-memory-server
git clone https://github.com/doobidoo/mcp-memory-service.git
cd mcp-memory-service

python3 -m venv venv
source venv/bin/activate
python3 install.py --skip-multi-client-prompt

mkdir -p /workspace/mcp-memory/db && mkdir -p /workspace/mcp-memory/backups

# create wrapper to simplyfy startup

cat > /doobidoo-mcp-memory-server/start-mcp.py << 'EOF'
#!/usr/bin/env python3
# start-mcp.py

import os
import sys
import subprocess

# Set environment variables
env = os.environ.copy()
env.update({
   'MCP_MEMORY_CHROMA_PATH': '/workspace/mcp-memory/db',
   'MCP_MEMORY_BACKUPS_PATH': '/workspace/mcp-memory/backups',
   'PYTORCH_ENABLE_MPS_FALLBACK': '1',
   'PYTORCH_CUDA_ALLOC_CONF': 'max_split_size_mb:128'
})

# Execute the service
sys.exit(subprocess.run([
   '/doobidoo-mcp-memory-server/mcp-memory-service/venv/bin/python3',
   '/doobidoo-mcp-memory-server/mcp-memory-service/scripts/run_memory_server.py'
], env=env).returncode)
EOF

chmod +x /doobidoo-mcp-memory-server/start-mcp.py

# Run command just for reference
# source /doobidoo-mcp-memory-server/mcp-memory-service/venv/bin/activate
# MCP_MEMORY_CHROMA_PATH=/workspace/mcp-memory/db \
# MCP_MEMORY_BACKUPS_PATH=/workspace/mcp-memory/backups \
# PYTORCH_ENABLE_MPS_FALLBACK=1 \
# PYTORCH_CUDA_ALLOC_CONF="max_split_size_mb:128" \
# python3 /doobidoo-mcp-memory-server/mcp-memory-service/scripts/run_memory_server.py
