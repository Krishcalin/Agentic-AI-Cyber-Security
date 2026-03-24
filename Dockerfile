FROM python:3.12-slim AS base

LABEL maintainer="Krishcalin"
LABEL description="Agentic AI Security Scanner — AI-powered source code security analysis"
LABEL org.opencontainers.image.source="https://github.com/Krishcalin/Agentic-AI-Cyber-Security"

# Security: non-root user
RUN groupadd -r scanner && useradd -r -g scanner -d /app -s /sbin/nologin scanner

WORKDIR /app

# Install dependencies first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Own files as scanner user
RUN chown -R scanner:scanner /app

USER scanner

# Default: run the scanner CLI
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "from core.engine import ScanEngine; e = ScanEngine(); e.initialize(); print('ok')" || exit 1

# Usage examples:
# docker build -t agentic-scan .
# docker run agentic-scan scan --file /data/app.py
# docker run -v $(pwd):/data agentic-scan scan --project /data
# docker run agentic-scan mcp-serve
