FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VEIL_HOST=0.0.0.0 \
    VEIL_PORT=8080

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 veilrelay \
    && mkdir -p /var/lib/veilrelay \
    && chown -R veilrelay:veilrelay /app /var/lib/veilrelay

USER veilrelay
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"

CMD ["veil", "serve", "--host", "0.0.0.0", "--port", "8080"]
