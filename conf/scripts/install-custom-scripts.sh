#!/bin/bash

SCRIPT_DIR="/custom-install-scripts"
PACKAGES_DIR="/install-packages"
LOG_FILE="/tmp/install-scripts-$(date +%Y%m%d-%H%M%S).log"
SUCCESS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

error() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" | tee -a "$LOG_FILE" >&2
}

log "Starting installation script execution"
log "Script directory: $SCRIPT_DIR"
log "Packages directory: $PACKAGES_DIR"
log "Log file: $LOG_FILE"

if [ ! -d "$SCRIPT_DIR" ]; then
  error "Directory $SCRIPT_DIR does not exist"
  exit 1
fi

cd "$SCRIPT_DIR" || {
  error "Failed to change to directory $SCRIPT_DIR"
  exit 1
}

mkdir -p "$PACKAGES_DIR"

SCRIPTS=$(find . -name "*.sh" -type f | sort)

if [ -z "$SCRIPTS" ]; then
  log "No .sh files found in $SCRIPT_DIR"
  exit 0
fi

log "Found $(echo "$SCRIPTS" | wc -l) script(s) to process"

for script in $SCRIPTS; do
  script_name=$(basename "$script" .sh)
  script_time=$(stat -c %Y "$script" 2>/dev/null || stat -f %m "$script" 2>/dev/null)
  target_package="$PACKAGES_DIR/${script_name}_${script_time}.tar.gz"
  
  log "----------------------------------------"
  log "Processing: $script_name"
  log "Target package: $(basename "$target_package")"
  
  # Check if target package already exists
  if [ -f "$target_package" ]; then
      log "SKIPPED: $script_name - package already exists"
      SKIP_COUNT=$((SKIP_COUNT + 1))
      continue
  fi
  
  # Remove any existing packages for this script
  log "Cleaning old packages for $script_name"
  rm -f "$PACKAGES_DIR/${script_name}_"*.tar.gz
  
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
  
  # Create timestamp before execution
  touch /tmp/before_install
  sleep 1
  
  log "Executing: $script_name"
  start_time=$(date +%s)
  
  if "./$script" 2>&1 | tee -a "$LOG_FILE"; then
      end_time=$(date +%s)
      duration=$((end_time - start_time))
      log "SUCCESS: $script_name completed in ${duration}s"
      
      # Create package from changes
      log "Creating package: $(basename "$target_package")"
      if find / -newer /tmp/before_install 2>/dev/null | \
         grep -v -E '^/(proc|sys|dev|tmp|var\/log|var\/cache|var\/lib\/apt)' | \
         tar -czf "$target_package" -T - 2>/dev/null; then
          log "Package created successfully"
          SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
      else
          error "Failed to create package for $script_name"
          FAIL_COUNT=$((FAIL_COUNT + 1))
      fi
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
log "Skipped: $SKIP_COUNT"
log "Failed: $FAIL_COUNT"
log "Log saved to: $LOG_FILE"

if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi