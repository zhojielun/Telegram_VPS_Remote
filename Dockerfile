FROM python:3.11-slim

LABEL maintainer="zhojielun"
LABEL description="Telegram VPS Remote Controller"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    vnstat \
    nethogs \
    iptables \
    net-tools \
    iproute2 \
    procps \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /var/lib/vps_bot/uploads /var/log/vps_bot

CMD ["python", "main.py"]
