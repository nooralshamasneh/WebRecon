FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt requirements.loc[k] ./
RUN if [ -f requirements.lock ]; then pip install --no-cache-dir -r requirements.txt -c requirements.lock gunicorn; \
    else pip install --no-cache-dir -r requirements.txt gunicorn; fi

COPY webrecon ./webrecon
RUN useradd --create-home --uid 10001 webrecon && mkdir /data && chown webrecon /data
USER webrecon

ENV WEBRECON_DATA_DIR=/data WEBRECON_HOST=0.0.0.0 WEBRECON_PORT=8080
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=3)"

# One process: the job queue runs in worker threads inside it (see docs/ARCHITECTURE.md).
CMD ["gunicorn", "-w", "1", "--threads", "8", "--timeout", "120", "-b", "0.0.0.0:8080", "webrecon:create_app()"]