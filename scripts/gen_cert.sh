#!/bin/sh
# Generates a self-signed certificate for the chat server (test/lab use only).
set -eu

DIR="${1:-certs}"
HOST="${2:-localhost}"

mkdir -p "$DIR"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$DIR/server.key" -out "$DIR/server.crt" -days 365 \
    -subj "/CN=$HOST" \
    -addext "subjectAltName=DNS:$HOST,DNS:localhost,IP:127.0.0.1"
chmod 600 "$DIR/server.key"
echo "Certificate: $DIR/server.crt (give this one to clients)"
echo "Private key: $DIR/server.key (keep it on the server only)"
