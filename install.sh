#!/bin/bash
set -euxo pipefail

mkdir -p local

sudo apt install -y wireguard
sudo apt install -y python3 python3-pip podman

sudo pip3 install requests tomli prettytable
pip3 install requests tomli prettytable
sudo podman build . -t bird-router

sed s#__INSTALL_DIR__#$PWD#g network-tools@.service.template > /tmp/network-tools@.service
sudo mv /tmp/network-tools@.service /etc/systemd/system/network-tools@.service
