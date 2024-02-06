#!/bin/bash
set -euxo pipefail

mkdir -p bin

cd bin
wget https://github.com/ginuerzh/gost/releases/download/v2.11.5/gost-linux-amd64-2.11.5.gz
gzip -d gost-linux-amd64-2.11.5.gz
mv gost-linux-amd64-2.11.5 gost
chmod a+x gost

wget https://github.com/fatedier/frp/releases/download/v0.54.0/frp_0.54.0_linux_amd64.tar.gz
tar -xzvf frp_0.54.0_linux_amd64.tar.gz --strip-component=1 frp_0.54.0_linux_amd64/frpc
tar -xzvf frp_0.54.0_linux_amd64.tar.gz --strip-component=1 frp_0.54.0_linux_amd64/frps
chmod a+x frpc
chmod a+x frps
rm frp_0.54.0_linux_amd64.tar.gz
