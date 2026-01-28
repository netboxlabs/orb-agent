#!/usr/bin/env bash
#
# entry point for orb-agent
#

agentstop1 () {
  printf "\rFinishing container.."
  exit 0
}

agentstop2 () {
  if [ -f "/var/run/orb-agent.pid"  ]; then
    ID=$(cat /var/run/orb-agent.pid)
    kill -15 $ID
  fi
}

if [ "${INSTALL_DRIVERS_PATH}" != '' ]; then
  cd "$(dirname "$(realpath "${INSTALL_DRIVERS_PATH}")")"
  echo "Installing additional drivers"
  pip3 install -r "${INSTALL_DRIVERS_PATH}" || {
    echo "Failed to install additional drivers from ${INSTALL_DRIVERS_PATH}" >&2
    exit 1
  }
fi

if [ "${INSTALL_WORKERS_PATH}" != '' ]; then
  cd "$(dirname "$(realpath "${INSTALL_WORKERS_PATH}")")"
  echo "Installing custom orb workers"
  pip3 install -r "${INSTALL_WORKERS_PATH}" || {
    echo "Failed to install custom orb workers from ${INSTALL_WORKERS_PATH}" >&2
    exit 1
  }
fi

# check geodb folder and extract db
cd /geo-db/
if [ -f "asn.mmdb.gz" ]; then
  gzip -d asn.mmdb.gz
  gzip -d city.mmdb.gz
fi

## Agent Configuration ##
DEFAULT_CONFIG_PATH="/opt/orb/default_config.yaml"
agent_args=("$@")

if [ -n "${FLEET_CLIENT_ID}" ] && [ -n "${FLEET_CLIENT_SECRET}" ]; then
  # Use packaged default config when fleet credentials are provided without an explicit config file.
  config_specified=false
  for arg in "${agent_args[@]}"; do
    case "${arg}" in
      --config|--config=*|-c|-c=*)
        config_specified=true
        break
        ;;
    esac
  done

  if [ "${config_specified}" = false ]; then
    if [ ${#agent_args[@]} -eq 0 ]; then
      agent_args=(run -c "${DEFAULT_CONFIG_PATH}")
    else
      run_specified=false
      for arg in "${agent_args[@]}"; do
        if [ "${arg}" = "run" ]; then
          run_specified=true
          break
        fi
      done
      if [ "${run_specified}" = true ]; then
        agent_args+=("--config" "${DEFAULT_CONFIG_PATH}")
      fi
    fi
  fi
fi

trap agentstop1 SIGINT
trap agentstop2 SIGTERM

# Restart failure tracking
MAX_QUICK_FAILURES=5
QUICK_FAILURE_THRESHOLD=10  # seconds
MAX_BACKOFF=60  # max backoff delay in seconds
consecutive_failures=0
last_start_time=0

# Main loop with failure detection and exponential backoff
while true
do
  # pid file exists
  if [ -f "/var/run/orb-agent.pid" ]; then
    PID=$(cat /var/run/orb-agent.pid)
    if [ ! -d "/proc/$PID" ]; then
       # Process not running - check if this was a quick failure
       current_time=$(date +%s)
       time_running=$((current_time - last_start_time))

       if [ "$last_start_time" -gt 0 ] && [ "$time_running" -lt "$QUICK_FAILURE_THRESHOLD" ]; then
         # Quick failure detected
         consecutive_failures=$((consecutive_failures + 1))
         echo "Agent failed quickly (ran for ${time_running}s). Consecutive failures: ${consecutive_failures}/${MAX_QUICK_FAILURES}"

         if [ "$consecutive_failures" -ge "$MAX_QUICK_FAILURES" ]; then
           echo "ERROR: Agent failed ${MAX_QUICK_FAILURES} times in quick succession. Exiting to prevent restart loop."
           echo "Common causes: port already in use (bind error), configuration error, missing dependencies."
           echo "Check logs above for specific error messages."
           rm -f /var/run/orb-agent.pid
           exit 1
         fi

         # Apply exponential backoff: min(MAX_BACKOFF, 2 * 2^failures)
         backoff_delay=$((2 * (1 << (consecutive_failures - 1))))
         if [ "$backoff_delay" -gt "$MAX_BACKOFF" ]; then
           backoff_delay=$MAX_BACKOFF
         fi
         echo "Applying exponential backoff: waiting ${backoff_delay}s before retry..."
         sleep "$backoff_delay"
       else
         # Not a quick failure or first start - reset counter
         if [ "$last_start_time" -gt 0 ]; then
           echo "Agent ran for ${time_running}s before exiting. Resetting failure counter."
           consecutive_failures=0
         fi
       fi

       echo "Cleaning stale PID file for $PID (process not running)"
       rm /var/run/orb-agent.pid
       # Fall through to next iteration which will start agent
    else
       # Process is running, wait
       sleep 5
    fi
  else
    # pid file doesn't exist, start agent
    echo "Starting orb-agent : /usr/local/bin/orb-agent with args ${#agent_args[@]}"
    last_start_time=$(date +%s)
    nohup /run-agent.sh "${agent_args[@]}" &
    sleep 2
    if [ -f "/nohup.out" ]; then
       tail -f /nohup.out &
    fi
  fi
done
