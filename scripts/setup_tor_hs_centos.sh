#!/bin/bash
# Setup Tor Hidden Service + SecureP2PChat signaling (CentOS 9 / LXC)
# Rulează ca root:  bash setup_tor_hs_centos.sh

set -euo pipefail

APP_DIR="${APP_DIR:-/root/secure_p2p_chat}"
HS_DIR="/var/lib/tor/securep2p_signal"
PORT="${PORT:-37422}"
SERVICE_NAME="securep2p-signal"

RED='\033[0;31m'
GRN='\033[0;32m'
CYN='\033[0;36m'
YLW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GRN}[OK]${NC} $*"; }
info() { echo -e "${CYN}[>>]${NC} $*"; }
warn() { echo -e "${YLW}[!!]${NC} $*"; }
die()  { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

echo "============================================"
echo " SecureP2PChat – Tor Hidden Service setup"
echo "============================================"
echo "APP_DIR=$APP_DIR  PORT=$PORT"
echo

# --- root? ---
if [[ "$(id -u)" -ne 0 ]]; then
  die "Rulează ca root: sudo bash $0"
fi

# --- proiect ---
[[ -f "$APP_DIR/signaling_server.py" ]] || die "Lipsă $APP_DIR/signaling_server.py – copiază proiectul mai întâi"
ok "Proiect găsit: $APP_DIR"

# --- Tor instalat ---
if ! command -v tor >/dev/null 2>&1; then
  info "Instalez Tor..."
  dnf install -y tor || yum install -y tor || die "Nu pot instala tor"
fi
ok "Tor: $(command -v tor)"

# --- user tor ---
TOR_USER="tor"
if ! id "$TOR_USER" >/dev/null 2>&1; then
  if id debian-tor >/dev/null 2>&1; then
    TOR_USER="debian-tor"
  else
    warn "User tor inexistent – folosesc root pentru HS dir (nu ideal)"
    TOR_USER="root"
  fi
fi
ok "User Tor: $TOR_USER"

# --- torrc ---
TORRC="/etc/tor/torrc"
[[ -f "$TORRC" ]] || die "Lipsă $TORRC"

# curăță eventuale linii vechi ale noastre, apoi adaugă bloc curat
if grep -q "securep2p_signal" "$TORRC" 2>/dev/null; then
  info "Curăț config vechi securep2p din torrc..."
  sed -i '/# SecureP2PChat/,+2d' "$TORRC" 2>/dev/null || true
  sed -i '/securep2p_signal/d' "$TORRC" 2>/dev/null || true
fi

cat >> "$TORRC" << TORBLOCK

# SecureP2PChat signaling hidden service
HiddenServiceDir $HS_DIR/
HiddenServicePort $PORT 127.0.0.1:$PORT
TORBLOCK
ok "torrc actualizat"

# --- director HS ---
mkdir -p "$HS_DIR"
chown -R "$TOR_USER:$TOR_USER" "$HS_DIR"
chmod 700 "$HS_DIR"
ok "HS dir: $HS_DIR"

# --- pornește Tor ---
systemctl enable tor >/dev/null 2>&1 || true
systemctl restart tor
sleep 2
systemctl is-active --quiet tor || die "Tor nu pornește – vezi: journalctl -u tor -n 50"
ok "Tor rulează"

# --- așteaptă hostname ---
info "Aștept generarea adresei .onion..."
ONION=""
for i in $(seq 1 30); do
  if [[ -f "$HS_DIR/hostname" ]]; then
    ONION=$(tr -d ' \r\n' < "$HS_DIR/hostname")
    [[ -n "$ONION" ]] && break
  fi
  sleep 1
done
[[ -n "$ONION" ]] || die "hostname .onion negăsit – verifică: ls -la $HS_DIR && journalctl -u tor -n 40"
ok "Onion: $ONION"

# --- PyNaCl ---
if ! python3 -c "import nacl" 2>/dev/null; then
  info "Instalez PyNaCl..."
  pip3 install PyNaCl || pip3 install --user PyNaCl || die "pip3 install PyNaCl a eșuat"
fi
ok "PyNaCl OK"

# --- systemd signaling ---
PY=$(command -v python3)
cat > /etc/systemd/system/${SERVICE_NAME}.service << UNIT
[Unit]
Description=SecureP2PChat Signaling Server (Tor HS backend)
After=network.target tor.service
Wants=tor.service

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$PY signaling_server.py --host 127.0.0.1 --port $PORT
Restart=always
RestartSec=3
# doar localhost – Tor face publicarea
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
systemctl restart "$SERVICE_NAME"
sleep 1
if systemctl is-active --quiet "$SERVICE_NAME"; then
  ok "Signaling service activ"
else
  warn "Serviciul nu e activ – vezi: journalctl -u $SERVICE_NAME -n 40"
  warn "Poți porni manual: cd $APP_DIR && python3 signaling_server.py --host 127.0.0.1 --port $PORT"
fi

# --- verificare port ---
if ss -tlnp 2>/dev/null | grep -q "127.0.0.1:$PORT"; then
  ok "Port $PORT ascultă pe 127.0.0.1"
else
  warn "Port $PORT nu apare încă pe 127.0.0.1 (poate serverul pornește greu)"
fi

# --- salvează info ---
INFO_FILE="$APP_DIR/ONION_ADDRESS.txt"
cat > "$INFO_FILE" << INFO
SecureP2PChat Tor Hidden Service
================================
Onion:  $ONION
Port:   $PORT
Data:   $(date -Iseconds)

Pe client (Windows):
  1. Pornește Tor Browser (sau Tor daemon)
  2. Setări app:
       Host  = $ONION
       Port  = $PORT
       TLS   = debifat (recomandat pe onion)
       SOCKS = 127.0.0.1  /  9150  (Tor Browser)
             sau 9050 (tor service pe Windows)
  3. pip install "python-socks[asyncio]"
  4. Salvează & reconectează

Comenzi utile pe server:
  systemctl status tor
  systemctl status $SERVICE_NAME
  cat $HS_DIR/hostname
  journalctl -u $SERVICE_NAME -f
INFO
ok "Salvat: $INFO_FILE"

echo
echo "============================================"
echo -e " ${GRN}GATA${NC}"
echo "============================================"
echo -e " Adresa onion:"
echo -e " ${CYN}$ONION${NC}"
echo
echo " Port: $PORT"
echo
echo " Client → Host = adresa de mai sus"
echo "          Port = $PORT"
echo "          SOCKS = 127.0.0.1:9150 (Tor Browser)"
echo
echo " Fișier: $INFO_FILE"
echo "============================================"
