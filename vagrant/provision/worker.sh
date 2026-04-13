#!/usr/bin/env bash
set -euo pipefail

JOIN_SCRIPT="/vagrant/vagrant/provision/join.sh"

if [ -f /etc/kubernetes/kubelet.conf ]; then
  echo "Worker already joined."
  exit 0
fi

echo "Waiting for join script from master..."
for i in $(seq 1 60); do
  if [ -f "${JOIN_SCRIPT}" ]; then
    break
  fi
  sleep 5
done

if [ ! -f "${JOIN_SCRIPT}" ]; then
  echo "Join script not found: ${JOIN_SCRIPT}"
  exit 1
fi

bash "${JOIN_SCRIPT}"

