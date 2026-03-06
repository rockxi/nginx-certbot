# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**UINX** — a web UI for managing Nginx reverse proxy configurations and issuing Let's Encrypt SSL certificates via Certbot. Everything runs in Docker.

## Setup

Create `.env` before starting:
```bash
cat >> .env << EOF
ADMIN_USERNAME=admin
ADMIN_PASSWORD=password
EOF
```

## Commands

```bash
# Start all services
docker-compose up --build -d

# Stop
docker-compose down

# View logs
docker-compose logs -f uinx

# Run locally (without Docker)
uv sync
uv run main.py
```

The UI is available at `http://localhost:1337`.

## Architecture

Three Docker services defined in `docker-compose.yml`:
- **nginx** (`nginx:alpine`) — reverse proxy, uses host network, config at `nginx/default.conf`
- **certbot** — runs `certbot renew` in a loop every 12h
- **uinx** — the FastAPI admin UI, runs on port 1337, mounts Docker socket and project directory

### Key files

- `main.py` — entire application: FastAPI app, Jinja2 templates (defined inline as strings), all routes, nginx config generation and parsing logic
- `nginx/default.conf` — live nginx config, directly edited by the app at runtime; `.bak` is auto-created on every write
- `certbot_init.sh` — manual certbot command reference (not used by the app)

### How the app works

The app controls nginx by directly reading/writing `nginx/default.conf` and calling `docker exec nginx-server nginx -s reload` (or `nginx -t` for testing).

SSL issuance flow (`/cert` route):
1. Writes a temporary HTTP-only config block for the domain (includes `/.well-known/acme-challenge/` and proxy_pass)
2. Reloads nginx
3. Runs `docker run --rm certbot/certbot certonly --webroot` using host paths from `HOST_PROJECT_PATH` env var
4. On success, replaces the block with a full HTTPS config (port 443 + HTTP→HTTPS redirect)

Adding a site (`/add`): appends an HTTP proxy block to the config and reloads nginx.

### Config generation

Three config templates are generated as Python f-strings in `main.py`:
- `get_pre_cert_config()` — HTTP proxy with ACME challenge support
- `get_http_challenge_config()` — HTTP with ACME only (redirect to HTTPS)
- `get_ssl_config()` — full HTTPS + HTTP redirect block pair

Nginx config is parsed with `parse_nginx_config()` using regex and string splitting on `server {`.

### Authentication

Session-based auth via `starlette.middleware.sessions`. Credentials come from `.env` (`ADMIN_USERNAME`, `ADMIN_PASSWORD`). `SECRET_KEY` is regenerated on each process start (sessions invalidated on restart).

## Important Notes

- The `HOST_PROJECT_PATH` env var must be the **host** absolute path to the project directory (set automatically via `${PWD}` in `docker-compose.yml`) — it is used for Docker volume mounts when running the certbot container.
- `EMAIL` for certbot is hardcoded in `main.py` at line 35 — change it before deploying.
- All services use `network_mode: "host"`, so nginx and the app see `localhost` services directly.
