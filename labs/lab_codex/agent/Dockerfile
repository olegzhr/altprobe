FROM node:22-trixie

ARG CODEX_VERSION=latest
RUN npm install -g @openai/codex@${CODEX_VERSION} \
 && npm cache clean --force

RUN useradd --create-home --uid 1001 --shell /bin/bash codex
COPY config.toml run.sh /opt/lab/
RUN chmod +x /opt/lab/run.sh

ENTRYPOINT ["/opt/lab/run.sh"]
