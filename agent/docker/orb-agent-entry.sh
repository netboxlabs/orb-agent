#!/usr/bin/env bash
#
# entry point for orb-agent
#

# Recreate writable dirs in case the user bind-mounted over /opt/orb.
mkdir -p /opt/orb/bin /opt/orb/pip-cache

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
DEFAULT_CONFIG_PATH="${ORB_DEFAULT_CONFIG:-/usr/local/share/orb-agent/default_config.yaml}"
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

# Default to 'run' subcommand if no args provided (preserve backward compatibility)
if [ ${#agent_args[@]} -eq 0 ]; then
  agent_args=(run)
fi

# Use exec to replace this shell process with the agent
# This makes the agent a direct child of tini, ensuring proper signal handling
exec /usr/local/bin/orb-agent "${agent_args[@]}"