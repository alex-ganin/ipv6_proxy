#!/bin/bash
echo "-------------------------------------------------"
echo ">-- Updating packages and installing dependencies"
apt-get update >/dev/null 2>&1
apt-get -y install gcc g++ make bc pwgen git vim curl htop build-essential speedtest-cli wget psmisc net-tools>/dev/null 2>&1
echo ">-- Setting up 3proxy"
git clone https://github.com/3proxy/3proxy.git
cd 3proxy
chmod +x src/
touch src/define.txt
echo "#define ANONYMOUS 1" >src/define.txt
sed -i '31r src/define.txt' src/proxy.h
ln -s Makefile.Linux Makefile
make
make install
systemctl disable 3proxy.service

echo ">-- NDP Proxy Daemon"
cd ~
git clone https://github.com/DanielAdolfsson/ndppd.git
cd ~/ndppd
make all && make install

echo ">-- Cleaning"
cd ~
rm -rf ./3proxy
rm -rf ./ndppd
