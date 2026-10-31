FROM node:22-trixie

ARG DSH_VERSION=0.1.7-rc.2
ENV DSH_VERSION=${DSH_VERSION}
RUN npm install -g pnpm @deepseek-ai/dsh@${DSH_VERSION} \
 && npm cache clean --force

RUN useradd --create-home --uid 1001 --shell /bin/bash dsh
COPY run.sh otel_push.js /opt/lab/
RUN chmod +x /opt/lab/run.sh

ENTRYPOINT ["/opt/lab/run.sh"]




