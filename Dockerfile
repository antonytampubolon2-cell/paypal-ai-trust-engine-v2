FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=false \
    TRUSTGUARD_OPENAPI_ENABLED=false \
    TRUSTGUARD_DATABASE_PATH=/data/trustguard.sqlite3

WORKDIR /app
COPY requirements.lock ./requirements.lock
RUN pip install --no-cache-dir -r requirements.lock \
    && useradd --system --uid 10001 --create-home trustguard \
    && mkdir -p /data \
    && chown trustguard:trustguard /data

COPY --chown=trustguard:trustguard app.py api_security.py skyfire_auth.py trustguard.py paypal_rest.py risk_scoring.py ./
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request; p=os.environ.get('PORT','8000'); urllib.request.urlopen(f'http://127.0.0.1:{p}/healthz', timeout=3)" || exit 1
CMD ["sh", "-c", "exec uvicorn app:app --host 0.0.0.0 --port \"${PORT:-8000}\" --workers 1 --no-access-log"]
