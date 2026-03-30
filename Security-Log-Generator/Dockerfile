FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /app

CMD ["sh", "-c", "mkdir -p /app/logs && touch /app/logs/ids.log /app/logs/access.log /app/logs/endpoint.log && python main.py"]
