#!/bin/sh
set -e

REPO_URL="https://github.com/rockxi/nginx-certbot"
INSTALL_DIR="nginx-certbot"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

print()  { printf "${CYAN}${1}${NC}\n"; }
ok()     { printf "${GREEN}✓ ${1}${NC}\n"; }
warn()   { printf "${YELLOW}⚠ ${1}${NC}\n"; }
error()  { printf "${RED}✗ ${1}${NC}\n"; exit 1; }

# ── Header ────────────────────────────────────────────────────────────────────
printf "\n${BOLD}"
echo "╔══════════════════════════════════════╗"
echo "║      UINX — Nginx + SSL Installer    ║"
echo "╚══════════════════════════════════════╝"
printf "${NC}\n"

# ── Check dependencies ────────────────────────────────────────────────────────
print "Checking dependencies..."

command -v git    > /dev/null 2>&1 || error "git is not installed"
command -v docker > /dev/null 2>&1 || error "docker is not installed"

if docker compose version > /dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose > /dev/null 2>&1; then
    COMPOSE="docker-compose"
else
    error "docker compose is not installed"
fi

docker info > /dev/null 2>&1 || error "Docker daemon is not running"

ok "All dependencies found"
echo ""

# ── Ask for configuration ─────────────────────────────────────────────────────
print "Configure UINX (press Enter to use default value):"
echo ""

# Username
printf "  Admin username [admin]: "
read ADMIN_USERNAME < /dev/tty
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"

# Password (hidden)
printf "  Admin password: "
stty -echo < /dev/tty 2>/dev/null || true
read ADMIN_PASSWORD < /dev/tty
stty echo < /dev/tty 2>/dev/null || true
echo ""
[ -z "$ADMIN_PASSWORD" ] && error "Admin password cannot be empty"

# Email
printf "  Email for Let's Encrypt: "
read CERTBOT_EMAIL < /dev/tty
[ -z "$CERTBOT_EMAIL" ] && error "Email cannot be empty (required for SSL certificates)"

echo ""

# ── Clone repository ──────────────────────────────────────────────────────────
if [ -d "$INSTALL_DIR/.git" ]; then
    warn "Directory '$INSTALL_DIR' already exists — pulling latest changes"
    git -C "$INSTALL_DIR" pull
else
    print "Cloning repository..."
    git clone "$REPO_URL" "$INSTALL_DIR"
    ok "Repository cloned"
fi

cd "$INSTALL_DIR"

# ── Write .env ────────────────────────────────────────────────────────────────
cat > .env << EOF
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
CERTBOT_EMAIL=${CERTBOT_EMAIL}
EOF
ok ".env created"

# ── Start services ────────────────────────────────────────────────────────────
print "Building and starting containers..."
$COMPOSE up --build -d
ok "Containers started"

# ── Done ──────────────────────────────────────────────────────────────────────
# Try to detect public IP for convenience
IP=$(curl -fsSL --max-time 3 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server-ip")

printf "\n${GREEN}${BOLD}UINX is up and running!${NC}\n\n"
echo "  UI:   http://${IP}:1337"
echo "  User: ${ADMIN_USERNAME}"
echo ""
echo "  To stop:    cd ${INSTALL_DIR} && ${COMPOSE} down"
echo "  To restart: cd ${INSTALL_DIR} && ${COMPOSE} up -d"
echo ""
