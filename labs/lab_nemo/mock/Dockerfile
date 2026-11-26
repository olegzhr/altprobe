FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY mock_openai.py /app/mock_openai.py
ENTRYPOINT ["python", "/app/mock_openai.py"]
