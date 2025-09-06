#!/bin/bash

source ./.env.sh

echo "*** Installation altprobe started***"
sudo apt-get update
sudo apt-get -y install libdaemon-dev libboost-all-dev libapr1-dev libaprutil1-dev
wget https://github.com/alertflex/altprobe/releases/download/v1.0.5/altprobe_1.0-5.deb
sudo dpkg -i altprobe_1.0-5.deb
sudo ldconfig

if [[ $INSTALL_REDIS == yes ]]
then
	echo "*** installation redis ***"
	sudo apt-get -y install redis-server 
fi