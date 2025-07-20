#!/bin/bash
PREFIX="$1"
shift

# Create temporary directory for pipes
TEMP_DIR=$(mktemp -d)
STDOUT_PIPE="$TEMP_DIR/stdout"
STDERR_PIPE="$TEMP_DIR/stderr"

mkfifo "$STDOUT_PIPE" "$STDERR_PIPE"

# Cleanup function
cleanup() {
    rm -rf "$TEMP_DIR"
    # Kill background processes
    jobs -p | xargs -r kill 2>/dev/null
}
trap cleanup EXIT INT TERM

# Start background loggers
{
    while IFS= read -r line; do
        printf "[%s][%s-INFO] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$PREFIX" "$line"
    done < "$STDOUT_PIPE"
} &
STDOUT_PID=$!

{
    while IFS= read -r line; do
        printf "[%s][%s-ERROR] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$PREFIX" "$line" >&2
    done < "$STDERR_PIPE"
} &
STDERR_PID=$!

# Execute the command with proper redirection
"$@" > "$STDOUT_PIPE" 2> "$STDERR_PIPE" &
MAIN_PID=$!

# Wait for the main process to complete
wait $MAIN_PID
EXIT_CODE=$?

# Clean up and exit with the same code
cleanup
exit $EXIT_CODE