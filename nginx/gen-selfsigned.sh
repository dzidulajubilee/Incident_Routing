#!/bin/sh
# Creates a self-signed certificate for nginx (lab use).
# Usage: ./nginx/gen-selfsigned.sh thehive.example.com
# For a real certificate, put server.crt (full chain) and server.key in nginx/certs/ instead.
set -e
NAME="${1:-localhost}"
DIR="$(dirname "$0")/certs"
mkdir -p "$DIR"
openssl req -x509 -nodes -newkey rsa:4096 -days 825 \
  -keyout "$DIR/server.key" -out "$DIR/server.crt" \
  -subj "/CN=$NAME" -addext "subjectAltName=DNS:$NAME,DNS:localhost"
chmod 644 "$DIR/server.crt"
chmod 600 "$DIR/server.key"
echo "Certificate for $NAME written to $DIR"
