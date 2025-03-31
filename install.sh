#!/bin/bash
set -euxo pipefail

mkdir -p local

sudo apt install -y wireguard
sudo apt install -y python3 python3-pip python3-venv podman socat

python3 -m venv venv
source venv/bin/activate
echo "$(which pip3)"
pip3 install requests tomli prettytable pydantic
deactivate

sudo podman build . -t bird-router

sed s#__INSTALL_DIR__#$PWD#g network-tools-new.service.template > /tmp/network-tools-new.service
sudo mv /tmp/network-tools-new.service /etc/systemd/system/network-tools-new.service
