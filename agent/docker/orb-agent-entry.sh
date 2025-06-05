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
  cd $(dirname "$(realpath "$INSTALL_DRIVERS_PATH")")
  echo "Installing additional drivers"
  pip3 install -r ${INSTALL_DRIVERS_PATH}
fi

if [ "${INSTALL_WORKERS_PATH}" != '' ]; then
  cd $(dirname "$(realpath "$INSTALL_WORKERS_PATH")")
  echo "Installing custom orb workers"
  pip3 install -r ${INSTALL_WORKERS_PATH}
fi

# check geodb folder and extract db
cd /geo-db/
if [ -f "asn.mmdb.gz" ]; then
  gzip -d asn.mmdb.gz
  gzip -d city.mmdb.gz
fi

## Agent Configuration ##
trap agentstop1 SIGINT
trap agentstop2 SIGTERM

# eternal loop
while true
do
  # pid file dont exist
  if [ ! -f "/var/run/orb-agent.pid"  ]; then
    # running orb-agent in background
    nohup /run-agent.sh "$@" &
    sleep 2
    if [ -d "/nohup.out" ]; then
       tail -f /nohup.out &
    fi
  else
    PID=$(cat /var/run/orb-agent.pid)
    if [ ! -d "/proc/$PID" ]; then
       # stop container
       echo "$PID is not running"
       rm /var/run/orb-agent.pid
       exit 1
    fi
    sleep 5
  fi
done
