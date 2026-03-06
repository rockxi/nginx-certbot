# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**UINX** — a web UI for managing Nginx reverse proxy configurations and issuing Let's Encrypt SSL certificates via Certbot. Everything runs in Docker.

## Setup

### One-command install
```bash
curl -fsSL https://raw.githubusercontent.com/rockxi/nginx-certbot/main/install.sh | sh
```

### Manual setup
Copy `.env.example` to `.env` and fill in values:
```bash
cp .env.example .env
```

Required variables:
- `ADMIN_USERNAME` — UI login
- `ADMIN_PASSWORD` — UI password
- `CERTBOT_EMAIL` — email for Let's Encrypt certificate notifications

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
- `nginx/default.conf` — live nginx config, directly edited by the app at runtime; **not tracked by git** (auto-created on startup if missing); `.bak` is auto-created on every write
- `install.sh` — one-command installer: prompts for credentials, clones repo, writes `.env`, runs `docker compose up`
- `certbot_init.sh` — manual certbot command reference (not used by the app)

### How the app works

On startup, if `nginx/default.conf` doesn't exist, the app creates an empty one automatically (`startup_event` in `main.py`).

The app controls nginx by directly reading/writing `nginx/default.conf` and calling `docker exec nginx-server nginx -s reload` (or `nginx -t` for testing).

SSL issuance flow (`/cert` route):
1. Validates domain (strict regex, alphanumeric + `-` + `.` only) and target URL (`http(s)://` required)
2. Checks that `CERTBOT_EMAIL` is set — shows error in UI if not
3. Writes a temporary HTTP-only config block for the domain (includes `/.well-known/acme-challenge/` and proxy_pass)
4. Reloads nginx
5. Runs `docker run --rm certbot/certbot certonly --webroot` using host paths from `HOST_PROJECT_PATH` env var
6. On success, replaces the block with a full HTTPS config (port 443 + HTTP→HTTPS redirect)

Adding a site (`/add`): validates domain and target, appends an HTTP proxy block, reloads nginx.

Raw config save (`/config/save`): saves file, runs `nginx -t`, and **auto-reverts** to previous config if syntax is invalid.

### Config generation

Three config templates as Python f-strings in `main.py`:
- `get_pre_cert_config()` — HTTP proxy with ACME challenge support
- `get_http_challenge_config()` — HTTP with ACME only (redirect to HTTPS)
- `get_ssl_config()` — full HTTPS + HTTP redirect block pair

Both `get_pre_cert_config()` and `get_ssl_config()` strip trailing slash from `target` before appending `/` in `proxy_pass` to avoid double slashes.

Nginx config is parsed with `parse_nginx_config()` using regex and string splitting on `server {`.

### Concurrency

A single module-level `_config_lock = asyncio.Lock()` is shared by `read_config()` and `write_config()` to prevent race conditions on the config file.

### Authentication

Session-based auth via `starlette.middleware.sessions`. Credentials come from `.env` (`ADMIN_USERNAME`, `ADMIN_PASSWORD`). `SECRET_KEY` is regenerated on each process start (sessions invalidated on restart).

## Important Notes

- `nginx/default.conf` is in `.gitignore` — it is created automatically on first run and managed entirely at runtime. Never commit it.
- `CERTBOT_EMAIL` must be set in `.env` — SSL issuance will fail with a clear UI error if it's missing.
- The `HOST_PROJECT_PATH` env var must be the **host** absolute path to the project directory (set automatically via `${PWD}` in `docker-compose.yml`) — used for Docker volume mounts when running the certbot container.
- All services use `network_mode: "host"`, so nginx and the app see `localhost` services directly.
- `certbot/conf/`, `certbot/www/`, and `html/` are gitignored except for `.gitkeep` files that preserve the directory structure after cloning.
