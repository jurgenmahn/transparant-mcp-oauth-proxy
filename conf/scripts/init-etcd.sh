#!/bin/bash
echo "Checking etcd initialization status..."

# Wait for etcd to be ready
for i in {1..30}; do
    if etcdctl --endpoints=http://localhost:2379 endpoint health &>/dev/null; then
        echo "etcd is ready"
        break
    fi
    echo "Waiting for etcd... ($i/30)"
    sleep 2
    [ $i -eq 30 ] && echo "etcd failed to start" && exit 1
done

# Check if initial import has already been done

if [[ "1" == "$(etcdctl get '/apisix/system/initial_import_done' --print-value-only=true)" ]]; then
    echo "Initial configuration already imported - skipping"
    exit 0
fi

echo "No initialization flag found - performing initial import"

# Load default configuration
node /scripts/import-export-etcd.js --format yaml --import /usr/local/apisix/conf/base-config.yaml

echo "✓ Initial configuration imported and flag set"