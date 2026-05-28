FROM python:3.11-slim

WORKDIR /app

# Install build tools for native extensions (confluent-kafka, cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libssl-dev \
    libffi-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first for layer caching
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e ".[dev]"

# Copy source
COPY tengen/ ./tengen/
COPY runbooks/ ./runbooks/

# Non-root user for security
RUN useradd -m -u 1000 tengen && chown -R tengen:tengen /app
USER tengen

EXPOSE 8080 8088

ENTRYPOINT ["python", "-m"]
CMD ["tengen.dashboard_main"]
