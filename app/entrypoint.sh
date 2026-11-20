#!/bin/sh
# The image clock is UTC. The host zone file is mounted at /host/localtime
# because a symlink at /etc/localtime cannot be replaced by a bind mount.
if [ -f /host/localtime ]; then
  rm -f /etc/localtime
  cp /host/localtime /etc/localtime
fi
exec python -u /app/server.py
