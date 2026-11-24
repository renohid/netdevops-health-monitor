FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first to leverage Docker layer caching
COPY pyproject.toml .
RUN pip install --upgrade pip && pip install .

# Copy application code and default target config
COPY app/ ./app/
COPY targets.yaml .

# Run as a non-root user for container security
RUN useradd --create-home --shell /bin/bash appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Native Python healthcheck (avoids installing curl in the slim image)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')" || exit 1

CMD [ "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]