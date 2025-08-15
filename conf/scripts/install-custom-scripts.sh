#!/bin/bash

SCRIPT_DIR="/custom-install-scripts"
LOG_FILE="/tmp/install-scripts-$(date +%Y%m%d-%H%M%S).log"
SUCCESS_COUNT=0
FAIL_COUNT=0

log() {
   echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

error() {
   echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" | tee -a "$LOG_FILE" >&2
}

log "Starting installation script execution"
log "Script directory: $SCRIPT_DIR"
log "Log file: $LOG_FILE"

if [ ! -d "$SCRIPT_DIR" ]; then
   error "Directory $SCRIPT_DIR does not exist"
   exit 1
fi

cd "$SCRIPT_DIR" || {
   error "Failed to change to directory $SCRIPT_DIR"
   exit 1
}

SCRIPTS=$(find . -name "*.sh" -type f | sort)

if [ -z "$SCRIPTS" ]; then
   log "No .sh files found in $SCRIPT_DIR"
   exit 0
fi

log "Found $(echo "$SCRIPTS" | wc -l) script(s) to execute"

for script in $SCRIPTS; do
   script_name=$(basename "$script")
   log "----------------------------------------"
   log "Executing: $script_name"
   
   if [ ! -r "$script" ]; then
       error "Cannot read $script_name"
       FAIL_COUNT=$((FAIL_COUNT + 1))
       continue
   fi
   
   chmod +x "$script" 2>/dev/null || {
       error "Failed to make $script_name executable"
       FAIL_COUNT=$((FAIL_COUNT + 1))
       continue
   }
   
   start_time=$(date +%s)
   
   if "./$script" 2>&1 | tee -a "$LOG_FILE"; then
       end_time=$(date +%s)
       duration=$((end_time - start_time))
       log "SUCCESS: $script_name completed in ${duration}s"
       SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
   else
       end_time=$(date +%s)
       duration=$((end_time - start_time))
       error "FAILED: $script_name failed after ${duration}s (exit code: $?)"
       FAIL_COUNT=$((FAIL_COUNT + 1))
   fi
done

log "----------------------------------------"
log "Execution complete"
log "Successful: $SUCCESS_COUNT"
log "Failed: $FAIL_COUNT"
log "Log saved to: $LOG_FILE"

if [ "$FAIL_COUNT" -gt 0 ]; then
   exit 1
fi