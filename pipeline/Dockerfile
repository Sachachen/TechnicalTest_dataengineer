FROM python:3.12-slim

WORKDIR /app

COPY pipeline/fetch_ipsum.py /app/fetch_ipsum.py

CMD ["python", "fetch_ipsum.py", "-o", "/app/data/ipsum.txt"]
