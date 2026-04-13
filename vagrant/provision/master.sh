#!/usr/bin/env bash
set -euo pipefail

CONTROL_IP="${1:-192.168.56.10}"

if [ -f /etc/kubernetes/admin.conf ]; then
  echo "Kubernetes already initialized."
  exit 0
fi

# init cluster
kubeadm init --apiserver-advertise-address="${CONTROL_IP}" --pod-network-cidr=10.244.0.0/16

# kubectl for vagrant user
mkdir -p /home/vagrant/.kube
cp -i /etc/kubernetes/admin.conf /home/vagrant/.kube/config
chown -R vagrant:vagrant /home/vagrant/.kube

# install Flannel CNI
sudo -u vagrant kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml

# generate join command for worker
kubeadm token create --print-join-command >/vagrant/vagrant/provision/join.sh
chmod +x /vagrant/vagrant/provision/join.sh

