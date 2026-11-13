#!/bin/sh
# Self-signed certificate for the DNS-override approach, where the charger keeps
# connecting to wss://ocpp.unitedchargers.com but your DNS points that name here.
# Only works if the charger does not verify the server certificate; test it.
set -e
# Usage: scripts/make-cert.sh [output-dir] [hostname]
OUT="${1:-./certs}"
HOST="${2:-ocpp.unitedchargers.com}"
mkdir -p "$OUT"
# CA:FALSE and serverAuth only: without them `openssl req -x509` makes the certificate a CA, and
# whoever got hold of privkey.pem could sign certificates for any site, valid wherever this one
# had been trusted.
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout "$OUT/privkey.pem" -out "$OUT/fullchain.pem" \
  -subj "/CN=$HOST" -addext "subjectAltName=DNS:$HOST,DNS:connect-api.unitedchargers.com" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"
chmod 600 "$OUT/privkey.pem"
echo "wrote $OUT/fullchain.pem and $OUT/privkey.pem for $HOST"
