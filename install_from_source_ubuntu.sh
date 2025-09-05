#!/bin/bash

echo "*** installation supp packages ***"
sudo apt-get update
sudo apt-get -y install build-essential make cmake automake autoconf autoconf-archive pkg-config libtool libdaemon-dev libboost-all-dev libapr1-dev libaprutil1-dev libssl-dev

sudo ldconfig

echo "*** installation libyaml  ***"
git clone https://github.com/yaml/libyaml --depth 1 --branch release/0.2.5
cd libyaml
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_TESTING=OFF  -DBUILD_SHARED_LIBS=ON ..
make
sudo make install
cd ../..

echo "*** installation hiredis ***"
git clone https://github.com/redis/hiredis.git
cd hiredis
make
sudo make install
cd ..

echo "*** installation activemq ***"
curl -L -O https://downloads.apache.org/activemq/activemq-cpp/3.9.5/activemq-cpp-library-3.9.5-src.tar.gz
tar xvfz activemq-cpp-library-3.9.5-src.tar.gz
cd activemq-cpp-library-3.9.5
./autogen.sh
./configure
make
sudo make install
sudo ldconfig
cd ..

echo "*** create altprobe package***"
cd src
make
sudo make install
sudo chmod o-rwx /etc/altprobe/altprobe.yaml
cd ../pkg
sudo mkdir -p dpkg/altprobe_1.0-5/usr/local/bin/
sudo cp /usr/local/bin/altprob* dpkg/altprobe_1.0-5/usr/local/bin/
sudo mkdir -p dpkg/altprobe_1.0-5/usr/local/lib/
sudo cp /usr/local/lib/libyaml.so dpkg/altprobe_1.0-5/usr/local/lib/
sudo cp /usr/local/lib/libhiredis.so.1.3.0 dpkg/altprobe_1.0-5/usr/local/lib/
sudo cp /usr/local/lib/libactivemq-cpp.so.19.0.5 dpkg/altprobe_1.0-5/usr/local/lib/libactivemq-cpp.so.19
sudo chown -R root:root dpkg
cd dpkg
sudo dpkg-deb --build altprobe_1.0-5



