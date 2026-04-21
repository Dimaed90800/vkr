#FROM python:3.11-slim
#
#ENV PYTHONDONTWRITEBYTECODE=1
#ENV PYTHONUNBUFFERED=1
#
#WORKDIR /app
#
#COPY backend/requirements.txt /tmp/requirements.txt
#RUN pip install --no-cache-dir --upgrade pip && \
#    pip install --no-cache-dir -r /tmp/requirements.txt
#
#COPY backend /app
#
#EXPOSE 8000
#
#CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies + Go toolchain for pinned CLI installs
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    golang \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# Install pinned security tools into toolbox container
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.7.1 && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0 && \
    go install github.com/ffuf/ffuf/v2@v2.1.0 && \
    cp /root/go/bin/nuclei /usr/local/bin/nuclei && \
    cp /root/go/bin/httpx /usr/local/bin/httpx && \
    cp /root/go/bin/ffuf /usr/local/bin/ffuf && \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/httpx /usr/local/bin/ffuf

COPY backend /app

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]