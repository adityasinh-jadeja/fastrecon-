# FastRecon v3.1 — Dockerfile
# Containerized environment for safe security scanning
# Includes optional Subfinder + Amass for enhanced subdomain enumeration

FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    nmap \
    curl \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Subfinder (latest release)
RUN ARCH=$(dpkg --print-architecture) && \
    SUBFINDER_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep '"tag_name"' | head -1 | cut -d'"' -f4) && \
    if [ -n "$SUBFINDER_VERSION" ]; then \
        wget -q "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION#v}_linux_${ARCH}.zip" -O /tmp/subfinder.zip && \
        unzip -o /tmp/subfinder.zip -d /usr/local/bin/ subfinder && \
        chmod +x /usr/local/bin/subfinder && \
        rm /tmp/subfinder.zip; \
    fi || echo "Subfinder install skipped (network unavailable)"

# Copy requirements and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directories for persistent data
RUN mkdir -p /app/reports /app/data

# Expose Flask port
EXPOSE 5000

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Default: Launch web UI
# Override with: docker run fastrecon python main.py -t example.com
CMD ["python", "main.py", "--web", "--host", "0.0.0.0", "--port", "5000"]
