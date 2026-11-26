FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir langchain-core==0.3.63
RUN mkdir -p /var/log/openshell && chmod 777 /app /var/log/openshell
COPY client.py /app/client.py
ENTRYPOINT ["python", "/app/client.py"]
