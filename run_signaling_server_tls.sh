#!/bin/bash
cd "$(dirname "$0")"
CERT="${SIGNAL_TLS_CERT:-./certs/server.crt}"
KEY="${SIGNAL_TLS_KEY:-./certs/server.key}"
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  echo "Lipsesc certurile. Rulează: bash scripts/gen_tls_cert.sh IP_PUBLIC_SAU_DOMENIU"
  exit 1
fi
exec python3 signaling_server.py --cert "$CERT" --key "$KEY" "$@"
