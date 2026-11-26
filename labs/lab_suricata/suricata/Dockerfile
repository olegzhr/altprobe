FROM jasonish/suricata:7.0
COPY run-traffic.py /usr/local/bin/run-traffic.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /usr/local/bin/run-traffic.py /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
