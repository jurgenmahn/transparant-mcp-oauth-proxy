#! /bin/bash

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
