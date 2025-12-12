FROM python:3.13-slim

# Çalışma dizinini oluştur
WORKDIR /app

# Sistem bağımlılıklarını yükle
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python bağımlılıklarını kopyala ve yükle
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama dosyalarını kopyala
COPY import_odc_to_neo4j.py /ingestion/import_odc_to_neo4j.py
COPY verify_neo4j.py /ingestion/verify_neo4j.py
COPY test_tools.py /ingestion/test_tools.py

# Ortam değişkenleri
ENV NEO4J_URI=bolt://host.docker.internal:7687
ENV NEO4J_USER=neo4j
ENV NEO4J_PASSWORD=password

# Script'i çalıştır
ENTRYPOINT ["python", "/ingestion/import_odc_to_neo4j.py"]
