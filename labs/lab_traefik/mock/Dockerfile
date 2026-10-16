FROM python:3.12-slim

WORKDIR /app

# Install runtime dependencies from the repo manifest.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the mock server sources (exclude .venv/.git via .dockerignore).
COPY ./main.py ./main.py
COPY ./services ./services

# MCP resources live under services/mcp/data and are resolved at runtime.
ENV MCP_DATA_DIR=/app/services/mcp/data
ENV MCP_CUR_DIR=/app/services

EXPOSE 8000

# Demo Mock Server: /mcp, /test-api, /inventory, /traces
CMD ["python", "/app/main.py", "--host", "0.0.0.0", "--port", "8000"]
