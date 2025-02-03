#!/bin/bash

# Get the absolute path of the current script's directory
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Default configuration file with absolute path
CONFIG_FLAG=""
CONFIG_FILE=""
LOG_FLAG=""
LOG_LEVEL=""

# Parse command-line options
# Note: The colon after "e" means that -e requires an argument.
while getopts "c:e:" opt; do
  case ${opt} in
    c )
      CONFIG_FILE=$OPTARG
      ;;
    e )
      LOG_LEVEL=$OPTARG
      ;;
    \? )
      echo "Usage: $0 [-c <config_file>] [-e <log_option>]"
      exit 1
      ;;
  esac
done

# LOG_LEVEL="info"
# CONFIG_FILE="$SCRIPT_DIR/build/configs/open5gs/udr.yaml"



if [[ "$CONFIG_FILE" ]]; then
  CONFIG_FLAG="-c"

  # Convert CONFIG_FILE to an absolute path (if not already absolute)
  if [[ ! "$CONFIG_FILE" = /* ]]; then
      CONFIG_FILE="$(realpath "$CONFIG_FILE")"
  fi

  # Check if the configuration file exists
  if [[ ! -f "$CONFIG_FILE" ]]; then
      echo "Error: Configuration file '$CONFIG_FILE' not found."
      exit 1
  fi
  echo "Using configuration file: $CONFIG_FILE"

fi

if [[ "$LOG_LEVEL" ]]; then
  LOG_FLAG="-e"
fi



cd "$(dirname "$0")"
echo "The current working directory is: $(pwd)"

cd build

gramine-manifest -Dgramine_log_level=error -Dshared_lib_path=/usr/lib/x86_64-linux-gnu -Dbuild_path=/home/trusslab/mehdi/5G/wisec/open5gs/build -Dconfig_flag=$CONFIG_FLAG -Dconfig_path=$CONFIG_FILE -Dlog_flag=$LOG_FLAG -Dlog_level=$LOG_LEVEL ../src/udr/udr.manifest.template ./src/udr/udr.manifest
gramine-sgx-sign --key /home/trusslab/.config/gramine/enclave-key.pem --manifest ./src/udr/udr.manifest --output ./src/udr/udr.manifest.sgx



# Define a cleanup function that kills the child process
cleanup() {
    echo "Caught termination signal, killing gramine-sgx (PID: $child_pid)..."
    kill -9 "$child_pid"
    wait "$child_pid"
    exit 0
}

# Trap SIGTERM and SIGINT signals and call cleanup
trap cleanup SIGTERM SIGINT


# gramine-direct src/udr/udr
gramine-sgx src/udr/udr &
# Capture its PID
child_pid=$!


# Wait for the child process to exit
wait "$child_pid"