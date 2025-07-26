#!/bin/bash

is_mounted() {
    mountpoint -q "$1" 2>/dev/null || 
    [ "$(stat -c %d "$1" 2>/dev/null)" != "$(stat -c %d "$1/.." 2>/dev/null)" ]
}

# Enforce volume mounts
REQUIRED_MOUNTS="/hydra-data"

for mount_path in $REQUIRED_MOUNTS; do
    if [ ! -d "$mount_path" ]; then
        echo "[INITITIALIZE] ERROR: Required directory $mount_path does not exist"
        exit 1
    fi
    
    if ! is_mounted "$mount_path"; then
        echo "[INITITIALIZE] ERROR: $mount_path is not mounted as volume. Use -v or docker-compose volumes."
        echo "[INITITIALIZE] Example: docker run -v /path/on/host/$mount_path:$mount_path ..."
        exit 1
    else
        echo "[INITITIALIZE] INFO: $mount_path is mounted as volume. Checking if we have to populate initial config"
        if [ -z "$(ls -A $mount_path)" ]; then
            echo "[INITITIALIZE] $mount_path is empty, copying initial config to the mountpoint"
            cp -a /init_data${mount_path} /
        else
            echo "[INITITIALIZE] $mount_path is not empty, assuming config is already populated, make sure an empty mountpoint is used if this is unintentional"
        fi
    fi
    
    echo "[INITITIALIZE] $mount_path properly mounted"
done

# load env vars generated during build.
source /.buildvars

echo set file and folder rights for hydra DB
chown nonroot:nonroot /hydra-data/hydra.sqlite
chmod 666 /hydra-data/hydra.sqlite

# NVM path
. /nvm/nvm.sh

# run always main container startup
/usr/bin/supervisord