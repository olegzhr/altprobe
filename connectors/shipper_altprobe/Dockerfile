FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir redis==5.0.8
COPY shipper.py /app/shipper.py
ENTRYPOINT ["python", "/app/shipper.py"]
