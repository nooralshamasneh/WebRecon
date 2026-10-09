FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .
RUN useradd --create-home webrecon && chown -R webrecon /app
USER webrecon

ENV WEBRECON_HOST=0.0.0.0 WEBRECON_PORT=8080
EXPOSE 8080

# One worker: scan results are kept in memory.
CMD ["gunicorn", "-w", "1", "--threads", "4", "--timeout", "600", "-b", "0.0.0.0:8080", "app:app"]
