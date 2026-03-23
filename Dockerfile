FROM python:3.11-slim

LABEL maintainer="rootdouer"
LABEL description="SupaHunt — Supabase Security Auditing Framework"
LABEL version="3.0.0"

WORKDIR /opt/supahunt

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY supahunt.py .
COPY modules/ modules/
COPY templates/ templates/

# Output directory
RUN mkdir -p /opt/supahunt/output
VOLUME ["/opt/supahunt/output"]

ENTRYPOINT ["python3", "supahunt.py"]
CMD ["--help"]
