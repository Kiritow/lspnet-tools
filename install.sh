#!/bin/bash
set -euxo pipefail

mkdir -p local

sudo apt install python3 python3-pip podman
sudo pip3 install requests tomli
pip3 install requests tomli
sudo podman build . -t bird-router

sed s#__INSTALL_DIR__#$PWD#g network-tools@.service.template > /tmp/network-tools@.service
sudo mv /tmp/network-tools@.service /etc/systemd/system/network-tools@.service
