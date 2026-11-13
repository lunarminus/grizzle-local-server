FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GRIZZLE_DATA_DIR=/data \
    GRIZZLE_PORT=9000

WORKDIR /app
COPY requirements.txt .
# requirements.txt pins every package, direct or not, with its hashes (see requirements.in).
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY grizzle_local ./grizzle_local
COPY tools ./tools
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# The server runs as this user. The image itself still starts as root, for one reason: the
# entrypoint has to hand over data volumes that an earlier image wrote as root. It drops to
# "grizzle" before starting Python (see docker-entrypoint.sh).
RUN useradd --system --uid 10001 --user-group --home-dir /app --shell /usr/sbin/nologin grizzle \
    && mkdir -p /data \
    && chown grizzle:grizzle /data \
    && chmod 0755 /usr/local/bin/docker-entrypoint.sh

VOLUME ["/data"]
EXPOSE 9000 8443

HEALTHCHECK --interval=60s --timeout=5s --start-period=10s \
  CMD python -c "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('GRIZZLE_PORT', '9000'), timeout=4).status == 200 else 1)"

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["python", "-m", "grizzle_local"]
