FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    GRIZZLE_DATA_DIR=/data \
    GRIZZLE_PORT=9000

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY grizzle_local ./grizzle_local
COPY tools ./tools

VOLUME ["/data"]
EXPOSE 9000 8443

HEALTHCHECK --interval=60s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9000/health', timeout=4).status == 200 else 1)"

CMD ["python", "-m", "grizzle_local"]
