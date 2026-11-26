FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    NEMO_GUARDRAILS_NO_USAGE_STATS=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends git gcc g++ \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      "nemoguardrails[server]==0.24.1" \
      "langchain-openai"

COPY config /config/altprobe
WORKDIR /app

EXPOSE 8000
ENTRYPOINT ["nemoguardrails"]
CMD ["server", "--verbose", "--config=/config", "--port=8000", "--default-config-id=altprobe"]
