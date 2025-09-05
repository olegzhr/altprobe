#!/bin/bash
INSTALL_REDIS=yes

echo "*** Installation altprobe started***"
sudo apt-get update
sudo apt-get -y install libdaemon-dev libboost-all-dev libapr1-dev libaprutil1-dev
sudo dpkg -i altprobe_1.0-5.deb
sudo ldconfig

if [[ $INSTALL_REDIS == yes ]]
then
	echo "*** installation redis ***"
	sudo apt-get -y install redis-server 
fi