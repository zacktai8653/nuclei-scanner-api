FROM projectdiscovery/nuclei:latest AS nuclei_bin

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nuclei_bin /usr/local/bin/nuclei /usr/local/bin/nuclei

RUN nuclei -update-templates

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner_api.py .

EXPOSE 8001

CMD ["python", "scanner_api.py"]
