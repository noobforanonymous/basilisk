# Basilisk — AI Red Teaming Framework
# Multi-stage build for smaller image size

FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md requirements.txt ./
COPY basilisk/ ./basilisk/

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Final stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/basilisk* /usr/local/bin/

# Copy payload database (needed at runtime)
COPY basilisk/payloads/ /app/basilisk/payloads/
COPY basilisk/report/templates/ /app/basilisk/report/templates/

# Create non-root user
RUN useradd -m -u 1000 basilisk && \
    chown -R basilisk:basilisk /app

USER basilisk

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD basilisk --help || exit 1

# Default command
ENTRYPOINT ["basilisk"]
CMD ["--help"]

# Labels (OpenContainers standard)
LABEL maintainer="Regaan <contact@rothackers.com>"
LABEL description="Basilisk — AI Red Teaming Framework with Smart Prompt Evolution"
LABEL version="1.0.7"
LABEL org.opencontainers.image.source="https://github.com/regaan/basilisk"
LABEL org.opencontainers.image.description="AI Red Teaming Framework — LLM security testing with genetic mutation and 29 attack modules"
LABEL org.opencontainers.image.licenses="AGPL-3.0"
LABEL org.opencontainers.image.title="Basilisk"
LABEL org.opencontainers.image.vendor="Rot Hackers"
LABEL org.opencontainers.image.url="https://github.com/regaan/basilisk"
LABEL org.opencontainers.image.documentation="https://github.com/regaan/basilisk/blob/main/README.md"
