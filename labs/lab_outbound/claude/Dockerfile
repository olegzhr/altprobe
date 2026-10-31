# Claude Code + Prempti в одном контейнере (hook, falco-плагин, interceptor).
FROM node:22-trixie

ARG CLAUDE_VERSION=2.1.316
ARG PREMPTI_VERSION=0.2.1

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    curl ca-certificates tar procps \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_VERSION} && npm cache clean --force

RUN curl -sSL "https://github.com/falcosecurity/prempti/releases/download/v${PREMPTI_VERSION}/prempti-${PREMPTI_VERSION}-linux-x86_64.tar.gz" \
      -o /tmp/prempti.tgz \
 && mkdir -p /opt/prempti-pkg \
 && tar xzf /tmp/prempti.tgz -C /opt/prempti-pkg --strip-components=1 \
 && rm /tmp/prempti.tgz

RUN useradd -m -u 1001 -s /bin/bash lab

COPY run.sh agent.sh /opt/lab/
RUN chmod +x /opt/lab/run.sh /opt/lab/agent.sh

ENTRYPOINT ["/opt/lab/run.sh"]
