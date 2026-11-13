#!/bin/bash
set -e
CN="${1:-localhost}"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
mkdir -p "$OUT_DIR"
openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
  -keyout "$OUT_DIR/server.key" \
  -out "$OUT_DIR/server.crt" \
  -subj "/CN=$CN"
chmod 600 "$OUT_DIR/server.key"
echo "Creat: $OUT_DIR/server.crt  $OUT_DIR/server.key"
echo "Start: python3 signaling_server.py --cert $OUT_DIR/server.crt --key $OUT_DIR/server.key"
