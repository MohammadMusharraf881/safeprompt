# Multi-stage / hardened production Dockerfile for SafePrompt Gateway
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final minimal runtime image
FROM python:3.11-slim AS runner

WORKDIR /app

# Security: Create non-root user and persistent storage directory
RUN groupadd -g 10001 safeprompt && \
    useradd -u 10001 -g safeprompt -s /bin/bash -m safeprompt && \
    mkdir -p /app/data

# Copy installed python dependencies from builder
COPY --from=builder /root/.local /home/safeprompt/.local

# Copy application and test code
COPY . .

# Ensure ownership for safeprompt user across app and data directories
RUN mkdir -p /app/data && chown -R safeprompt:safeprompt /app /home/safeprompt

ENV PATH=/home/safeprompt/.local/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ENVIRONMENT=production

USER safeprompt

EXPOSE 8000

# Container Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]