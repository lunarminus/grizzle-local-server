#!/bin/sh
# Self-signed certificate for the DNS-override approach, where the charger keeps
# connecting to wss://ocpp.unitedchargers.com but your DNS points that name here.
# Only works if the charger does not verify the server certificate; test it.
set -e
# Usage: scripts/make-cert.sh [output-dir] [hostname]
OUT="${1:-./certs}"
HOST="${2:-ocpp.unitedchargers.com}"
mkdir -p "$OUT"
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout "$OUT/privkey.pem" -out "$OUT/fullchain.pem" \
  -subj "/CN=$HOST" -addext "subjectAltName=DNS:$HOST,DNS:connect-api.unitedchargers.com"
echo "wrote $OUT/fullchain.pem and $OUT/privkey.pem for $HOST"
