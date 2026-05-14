# SecretFinder Advanced Edition - Dockerized
# Build: docker build -t secretfinder .
# Run:   docker run --rm -v $(pwd)/output:/app/output secretfinder -i https://example.com/app.js -o output/result.html

FROM python:3.12-slim

# Labels for metadata
LABEL org.opencontainers.image.title="SecretFinder Advanced"
LABEL org.opencontainers.image.description="Professional tool to discover secrets in JavaScript files"
LABEL org.opencontainers.image.authors="Xnuvers007 <https://github.com/Xnuvers007/SecretFinder>"

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxml2-dev \
    libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user and setup directories
RUN useradd -m scanner && \
    mkdir -p /app/output && \
    chown -R scanner:scanner /app

# Copy project files
COPY --chown=scanner:scanner . .

# Switch to non-root user
USER scanner

# Ensure output directory is a volume
VOLUME ["/app/output"]

ENTRYPOINT ["python", "SecretFinder.py"]
CMD ["--help"]
