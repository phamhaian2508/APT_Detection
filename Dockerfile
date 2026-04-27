FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN python -m pip install --upgrade pip setuptools wheel \
    && pip install -r requirements.txt

COPY application.py .
COPY backend ./backend
COPY flow ./flow
COPY models ./models
COPY static ./static
COPY templates ./templates
COPY tests ./tests
COPY README.md .

RUN mkdir -p /app/data /app/logs

EXPOSE 5000

CMD ["python", "application.py"]
