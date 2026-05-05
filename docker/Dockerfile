FROM ubuntu:jammy

RUN apt-get update && apt-get -y install wget libyaml-cpp-dev libdaemon-dev libboost-all-dev libmodsecurity3
RUN wget https://github.com/alertflex/altprobe/releases/download/v1.0.5/altprobe_1.0-5.deb 
RUN dpkg -i altprobe_1.0-5.deb && ldconfig

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
