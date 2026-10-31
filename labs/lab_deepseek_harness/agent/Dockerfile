FROM node:22-trixie

ARG DSH_VERSION=latest
RUN npm install -g @deepseek-ai/dsh@${DSH_VERSION} \
 && npm cache clean --force

RUN useradd --create-home --uid 1001 --shell /bin/bash dsh
COPY run.sh /opt/lab/run.sh
RUN chmod +x /opt/lab/run.sh

ENTRYPOINT ["/opt/lab/run.sh"]
