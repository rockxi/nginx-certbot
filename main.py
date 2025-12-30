import os
import re
import asyncio
import logging
import secrets
from typing import Optional, List
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import APIKeyCookie
from starlette.middleware.sessions import SessionMiddleware
from jinja2 import Environment, DictLoader, select_autoescape
from dotenv import find_dotenv, load_dotenv
load_dotenv(find_dotenv())

# ==========================================
# КОНФИГУРАЦИЯ (SETTINGS)
# ==========================================

# Учетные данные
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "password")
SECRET_KEY = secrets.token_hex(32)

# Пути (относительно main.py)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NGINX_CONF_PATH = os.path.join(BASE_DIR, "nginx/default.conf")

# Внешний путь (на хосте) для передачи в команду docker run
HOST_BASE_DIR = os.environ.get("HOST_PROJECT_PATH", BASE_DIR)
HOST_CERTBOT_CONF_DIR = os.path.join(HOST_BASE_DIR, "certbot/conf")
HOST_CERTBOT_WWW_DIR = os.path.join(HOST_BASE_DIR, "certbot/www")

# Настройки Docker и Email
NGINX_CONTAINER_NAME = "nginx-server"
EMAIL = "stroganovf.t@gmail.com"

# Логирование
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("uinx")

app = FastAPI(title="UINX", docs_url=None, redoc_url=None)
# Используем сессии для flash-сообщений и простой авторизации
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# ==========================================
# HTML ШАБЛОНЫ (UI)
# ==========================================

HTML_BASE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UINX /// ADMIN</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Space Mono', monospace; background-color: #050505; color: #e0e0e0; }
        .neon-border { box-shadow: 0 0 5px #00ff9d, inset 0 0 5px #00ff9d; border: 1px solid #00ff9d; }
        .neon-text { text-shadow: 0 0 5px #00ff9d; color: #00ff9d; }
        .glass { background: rgba(20, 20, 20, 0.9); border: 1px solid #333; }
        .btn { @apply px-4 py-2 uppercase text-xs font-bold tracking-widest transition-all duration-200; }
        .btn-primary { background: #00ff9d; color: #000; }
        .btn-primary:hover { background: #fff; box-shadow: 0 0 15px #00ff9d; }
        .btn-danger { border: 1px solid #ff3333; color: #ff3333; background: transparent; }
        .btn-danger:hover { background: #ff3333; color: #000; box-shadow: 0 0 10px #ff3333; }
        .input-cyber { @apply w-full bg-black border border-gray-700 p-3 text-white focus:border-[#00ff9d] focus:outline-none focus:ring-1 focus:ring-[#00ff9d]; }
        
        /* Loading overlay */
        #loader { display: none; }
        .loader-spin { border: 4px solid #111; border-top: 4px solid #00ff9d; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
    <script>
        function showLoader(msg) {
            document.getElementById('loader').style.display = 'flex';
            document.getElementById('loader-text').innerText = msg;
        }
    </script>
</head>
<body class="min-h-screen flex flex-col relative">
    <!-- Overlay Loader -->
    <div id="loader" class="fixed inset-0 bg-black/90 z-50 flex flex-col items-center justify-center backdrop-blur-sm">
        <div class="loader-spin mb-4"></div>
        <div id="loader-text" class="text-[#00ff9d] animate-pulse">PROCESSING...</div>
    </div>

    <nav class="border-b border-gray-800 bg-black/50 backdrop-blur-md sticky top-0 z-40">
        <div class="container mx-auto p-4 flex justify-between items-center">
            <div class="text-2xl font-bold tracking-tighter neon-text">UINX <span class="text-xs text-gray-500 align-top">SYS.ADMIN</span></div>
            {% if user %}
            <div class="flex items-center gap-4">
                <span class="text-xs text-gray-500 hidden md:inline">LOGGED_IN_AS: {{ user }}</span>
                <form action="/logout" method="post">
                    <button class="text-gray-400 hover:text-white text-sm hover:underline">[LOGOUT]</button>
                </form>
            </div>
            {% endif %}
        </div>
    </nav>

    <main class="flex-grow container mx-auto p-4 md:p-8">
        <!-- Flash Messages -->
        {% if messages %}
            {% for msg in messages %}
            <div class="mb-6 p-4 border-l-4 {{ 'border-[#00ff9d] bg-[#00ff9d]/10' if 'Success' in msg else 'border-red-500 bg-red-900/20' }}">
                <p class="text-sm font-bold">{{ msg }}</p>
            </div>
            {% endfor %}
        {% endif %}

        {% block content %}{% endblock %}
    </main>
</body>
</html>
"""

HTML_LOGIN = """
{% extends "base.html" %}
{% block content %}
<div class="flex justify-center items-center h-[60vh]">
    <div class="glass p-8 w-full max-w-md neon-border relative overflow-hidden">
        <div class="absolute top-0 right-0 p-2 text-[10px] text-[#00ff9d] opacity-50">SECURE_GATEWAY</div>
        <h2 class="text-2xl mb-8 font-bold text-white tracking-widest text-center">AUTHENTICATE</h2>
        <form method="POST" action="/login">
            <div class="mb-6">
                <label class="block text-xs text-gray-500 mb-2 uppercase">Username</label>
                <input type="text" name="username" class="input-cyber" required autofocus autocomplete="off">
            </div>
            <div class="mb-8">
                <label class="block text-xs text-gray-500 mb-2 uppercase">Password</label>
                <input type="password" name="password" class="input-cyber" required>
            </div>
            <button type="submit" class="w-full btn btn-primary">ENTER_SYSTEM</button>
        </form>
    </div>
</div>
{% endblock %}
"""

HTML_DASHBOARD = """
{% extends "base.html" %}
{% block content %}
<div class="grid grid-cols-1 lg:grid-cols-12 gap-8">
    
    <!-- LEFT PANEL: CONTROLS -->
    <div class="lg:col-span-4 space-y-6">
        <!-- Add Proxy Widget -->
        <div class="glass p-6">
            <h3 class="text-lg font-bold text-white mb-4 border-b border-gray-800 pb-2 flex justify-between">
                <span>NEW_CONNECTION</span>
                <span class="text-[#00ff9d] text-xs self-center">● ONLINE</span>
            </h3>
            <form action="/add" method="POST" onsubmit="showLoader('UPDATING NGINX CONFIG...')">
                <div class="mb-4">
                    <label class="block text-xs text-gray-500 mb-1">SERVER_NAME (DOMAIN)</label>
                    <input type="text" name="domain" placeholder="app.rockxi.ru" class="input-cyber" required>
                </div>
                <div class="mb-6">
                    <label class="block text-xs text-gray-500 mb-1">PROXY_TARGET (URL)</label>
                    <input type="text" name="target" placeholder="http://localhost:3000" class="input-cyber" required>
                </div>
                <button type="submit" class="w-full btn btn-primary flex justify-center items-center gap-2">
                    <span>INITIALIZE</span> <span>+</span>
                </button>
            </form>
        </div>

        <!-- System Controls -->
        <div class="glass p-6">
            <h3 class="text-sm font-bold text-gray-400 mb-4">SYSTEM_OPERATIONS</h3>
            <div class="grid grid-cols-2 gap-3">
                <form action="/nginx/test" method="POST" onsubmit="showLoader('TESTING CONFIG...')">
                    <button class="w-full border border-gray-600 hover:border-white text-gray-300 py-2 text-xs hover:bg-white/5 transition-colors">TEST CONFIG</button>
                </form>
                <form action="/nginx/reload" method="POST" onsubmit="showLoader('RELOADING NGINX...')">
                    <button class="w-full border border-gray-600 hover:border-white text-gray-300 py-2 text-xs hover:bg-white/5 transition-colors">FORCE RELOAD</button>
                </form>
            </div>
        </div>
    </div>

    <!-- RIGHT PANEL: ACTIVE NODES -->
    <div class="lg:col-span-8">
        <h3 class="text-xl font-bold text-white mb-6 flex items-center gap-2">
            ACTIVE_NODES <span class="bg-gray-800 text-gray-400 text-xs px-2 py-0.5 rounded">{{ sites|length }}</span>
        </h3>
        
        <div class="space-y-4">
            {% for site in sites %}
            <div class="glass p-5 flex flex-col md:flex-row justify-between items-start md:items-center group hover:border-gray-500 transition-colors">
                <div class="mb-4 md:mb-0">
                    <div class="flex items-center gap-3">
                        {% if site.ssl %}
                            <div class="w-2 h-2 bg-[#00ff9d] rounded-full shadow-[0_0_8px_#00ff9d]"></div>
                            <span class="text-lg font-bold text-white">{{ site.domain }}</span>
                            <span class="text-[10px] border border-[#00ff9d] text-[#00ff9d] px-1">SSL/TLS</span>
                        {% else %}
                            <div class="w-2 h-2 bg-yellow-500 rounded-full animate-pulse"></div>
                            <span class="text-lg font-bold text-white">{{ site.domain }}</span>
                            <span class="text-[10px] border border-yellow-500 text-yellow-500 px-1">HTTP_ONLY</span>
                        {% endif %}
                    </div>
                    <div class="text-gray-500 text-xs font-mono mt-1 pl-5">
                        └──> {{ site.target }}
                    </div>
                </div>

                <div class="flex items-center gap-3 w-full md:w-auto">
                    {% if not site.ssl %}
                    <form action="/cert" method="POST" onsubmit="showLoader('EXECUTING CERTBOT SEQUENCE...\nStep 1: Verify HTTP\nStep 2: Request Cert\nStep 3: Update Nginx')">
                        <input type="hidden" name="domain" value="{{ site.domain }}">
                        <input type="hidden" name="target" value="{{ site.target }}">
                        <button class="btn border border-[#00ff9d] text-[#00ff9d] hover:bg-[#00ff9d] hover:text-black w-full md:w-auto">
                            INSTALL SSL
                        </button>
                    </form>
                    {% endif %}
                    
                    <form action="/delete" method="POST" onsubmit="return confirm('TERMINATE NODE {{ site.domain }}?');">
                        <input type="hidden" name="domain" value="{{ site.domain }}">
                        <button class="btn btn-danger w-full md:w-auto">X</button>
                    </form>
                </div>
            </div>
            {% else %}
            <div class="p-8 text-center border border-dashed border-gray-800 text-gray-600">
                NO ACTIVE CONFIGURATIONS DETECTED
            </div>
            {% endfor %}
        </div>

        <!-- Raw Config Viewer -->
        <div class="mt-8">
            <details class="text-xs text-gray-500 cursor-pointer">
                <summary class="hover:text-white transition-colors mb-2">VIEW_RAW_CONFIG_TAIL</summary>
                <pre class="bg-black border border-gray-800 p-4 overflow-x-auto text-gray-400 font-mono">{{ raw_config }}</pre>
            </details>
        </div>
    </div>
</div>
{% endblock %}
"""

# Инициализация Jinja2 с DictLoader для решения проблемы наследования
templates_dict = {
    "base.html": HTML_BASE,
    "login.html": HTML_LOGIN,
    "dashboard.html": HTML_DASHBOARD
}
jinja_env = Environment(
    loader=DictLoader(templates_dict),
    autoescape=select_autoescape(['html', 'xml'])
)

def render_template(template_name: str, context: dict):
    template = jinja_env.get_template(template_name)
    return HTMLResponse(template.render(**context))


# ==========================================
# ЛОГИКА NGINX И СИСТЕМНЫЕ КОМАНДЫ
# ==========================================

async def run_command(cmd: str):
    """Асинхронный запуск shell команды"""
    logger.info(f"Exec: {cmd}")
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    return process.returncode, stdout.decode().strip(), stderr.decode().strip()

async def read_config():
    if not os.path.exists(NGINX_CONF_PATH):
        return ""
    async with asyncio.Lock(): # Простейшая защита от гонки
        with open(NGINX_CONF_PATH, 'r') as f:
            return f.read()

async def write_config(content: str):
    async with asyncio.Lock():
        # Бэкап
        if os.path.exists(NGINX_CONF_PATH):
            os.system(f"cp {NGINX_CONF_PATH} {NGINX_CONF_PATH}.bak")
        with open(NGINX_CONF_PATH, 'w') as f:
            f.write(content)

def parse_nginx_config(content: str):
    """
    Парсит конфиг, находит server blocks.
    Возвращает список словарей.
    """
    sites = []
    # Грубое разбиение по "server {"
    blocks = content.split('server {')
    seen = set()

    for block in blocks[1:]:
        full_block = "server {" + block
        
        # Извлекаем server_name
        sn_match = re.search(r'server_name\s+([^;]+);', full_block)
        if not sn_match: continue
        domain = sn_match.group(1).strip().split()[0] # Берем первый, если их несколько

        # Пропускаем localhost/ip если есть
        if domain == "localhost" or domain == "_": continue

        # Извлекаем proxy_pass или redirect
        proxy_match = re.search(r'proxy_pass\s+([^;]+);', full_block)
        target = proxy_match.group(1).strip() if proxy_match else "REDIRECT/STATIC"

        # Проверка SSL (наличие 443 или путей к сертификатам)
        is_ssl = ('listen 443' in full_block) or ('ssl_certificate' in full_block)

        # Дедупликация: если у домена есть SSL блок, он считается SSL-защищенным
        if domain in seen:
            for s in sites:
                if s['domain'] == domain:
                    if is_ssl: s['ssl'] = True
                    if proxy_match: s['target'] = target # SSL блок обычно содержит реальный таргет
            continue
        
        seen.add(domain)
        sites.append({'domain': domain, 'target': target, 'ssl': is_ssl})
    
    return sites

def remove_domain_block(content: str, domain: str) -> str:
    """Удаляет ВСЕ блоки server {}, где встречается server_name domain;"""
    blocks = content.split('server {')
    new_blocks = [blocks[0]] # Все что до первого сервера
    
    for block in blocks[1:]:
        full_block = "server {" + block
        # Проверяем точное совпадение домена
        if not re.search(rf'server_name\s+{re.escape(domain)}[;\s]', full_block):
            new_blocks.append(full_block)
            
    return "".join(new_blocks)

# === ШАГ 1: Конфиг для подтверждения (HTTP) ===
def get_http_challenge_config(domain: str) -> str:
    return f"""
server {{
    listen 80;
    server_name {domain};

    location /.well-known/acme-challenge/ {{
        root /var/www/certbot;
    }}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}
"""

def get_pre_cert_config(domain: str, target: str) -> str:
    if target[-1] == '/':
        target = target[:-1]
    """Конфиг, который создается при добавлении сайта (До SSL)"""
    return f"""
server {{
    listen 80;
    server_name {domain};

    location /.well-known/acme-challenge/ {{
        root /var/www/certbot;
    }}

    location / {{
        proxy_pass {target}/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
}}
"""

# === ШАГ 4: Финальный конфиг (HTTPS + HTTP Redirect) ===
def get_ssl_config(domain: str, target: str) -> str:
    return f"""
server {{
    listen 80;
    server_name {domain};

    location /.well-known/acme-challenge/ {{
        root /var/www/certbot;
    }}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}

server {{
    listen 443 ssl;
    http2 on;
    server_name {domain};

    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    error_page 404 500 502 503 504 /error.html;

    location = /error.html {{
        root /usr/share/nginx/html;
        internal;
    }}

    location / {{
        proxy_pass {target}/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # WebSocket Support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }}
}}
"""

# ==========================================
# МАРШРУТЫ (ROUTES)
# ==========================================

# Зависимость авторизации
async def get_current_user(request: Request):
    user = request.session.get("user")
    if not user:
        return None
    return user

async def require_auth(request: Request):
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return user

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return render_template("login.html", {"request": request, "messages": []})

@app.post("/login")
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        request.session["user"] = username
        return RedirectResponse("/", status_code=302)
    return render_template("login.html", {"request": request, "messages": ["Error: Invalid Credentials"]})

@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, user: str = Depends(require_auth)):
    config_content = await read_config()
    sites = parse_nginx_config(config_content)
    
    # Флеш сообщения через сессию
    msgs = request.session.pop("messages", [])
    
    raw = config_content[-1500:] if len(config_content) > 1500 else config_content

    return render_template("dashboard.html", {
        "request": request, 
        "user": user, 
        "sites": sites, 
        "raw_config": raw,
        "messages": msgs
    })

# --- ОСНОВНЫЕ ДЕЙСТВИЯ ---

@app.post("/add")
async def add_site(request: Request, domain: str = Form(...), target: str = Form(...), user: str = Depends(require_auth)):
    domain = domain.strip()
    target = target.strip()
    
    content = await read_config()
    
    if f"server_name {domain};" in content:
        request.session["messages"] = [f"Error: Domain {domain} already exists!"]
        return RedirectResponse("/", status_code=302)

    # 1. Создаем HTTP конфиг (Pre-Cert)
    new_block = get_pre_cert_config(domain, target)
    await write_config(content + "\n" + new_block)
    
    # 2. Reload Nginx
    code, out, err = await run_command(f"docker exec {NGINX_CONTAINER_NAME} nginx -s reload")
    
    if code != 0:
        request.session["messages"] = [f"Error Nginx Reload: {err}"]
    else:
        request.session["messages"] = [f"Success: Added {domain}. Press 'INSTALL SSL' to secure."]
        
    return RedirectResponse("/", status_code=302)

@app.post("/delete")
async def delete_site(request: Request, domain: str = Form(...), user: str = Depends(require_auth)):
    content = await read_config()
    new_content = remove_domain_block(content, domain)
    
    if len(new_content) == len(content):
        request.session["messages"] = ["Error: Domain block not found."]
    else:
        await write_config(new_content)
        await run_command(f"docker exec {NGINX_CONTAINER_NAME} nginx -s reload")
        request.session["messages"] = [f"Success: Removed {domain}"]
        
    return RedirectResponse("/", status_code=302)

@app.post("/cert")
async def generate_cert(request: Request, domain: str = Form(...), target: str = Form(...), user: str = Depends(require_auth)):
    """
    Полный цикл получения сертификата по вашему ТЗ.
    """
    # 1. Убеждаемся, что конфиг правильный (HTTP only c well-known)
    # Удаляем старый блок и пишем чистый HTTP блок для certbot
    content = await read_config()
    content_no_domain = remove_domain_block(content, domain)
    
    # Шаг 2 из промпта: server { listen 80; ... location /.well-known ... }
    # Используем get_pre_cert_config, так как он содержит и прокси, и well-known.
    # Это позволяет сайту работать по HTTP пока мы получаем серт.
    temp_config_block = get_pre_cert_config(domain, target)
    
    await write_config(content_no_domain + "\n" + temp_config_block)
    
    # 3. Проверка и перезапуск (Reload)
    code_test, out_test, err_test = await run_command(f"docker exec {NGINX_CONTAINER_NAME} nginx -t")
    if code_test != 0:
        request.session["messages"] = [f"Error Config Check: {err_test}"]
        return RedirectResponse("/", status_code=302)
        
    await run_command(f"docker exec {NGINX_CONTAINER_NAME} nginx -s reload")
    
    # 4. Запуск Certbot (Команда из init.sh, адаптированная под пути)
    # Важно: используем абсолютные пути хоста для volume mapping
    
    cmd_certbot = (
        f"docker run --rm "
        f"-v {HOST_CERTBOT_CONF_DIR}:/etc/letsencrypt "
        f"-v {HOST_CERTBOT_WWW_DIR}:/var/www/certbot "
        f"certbot/certbot certonly --webroot "
        f"--webroot-path /var/www/certbot "
        f"--email {EMAIL} -d {domain} "
        f"--agree-tos --no-eff-email --force-renewal"
    )
    
    code_cert, out_cert, err_cert = await run_command(cmd_certbot)
    
    if code_cert != 0:
        # Логируем ошибку, но конфиг оставляем HTTP, чтобы сайт работал
        request.session["messages"] = [f"Certbot Error: {err_cert}\nOutput: {out_cert}"]
        return RedirectResponse("/", status_code=302)

    # 5. Успех -> Меняем конфиг на HTTPS
    # Читаем заново (вдруг что изменилось), удаляем темп блок
    content_re = await read_config()
    content_clean = remove_domain_block(content_re, domain)
    
    ssl_block = get_ssl_config(domain, target)
    await write_config(content_clean + "\n" + ssl_block)
    
    # 6. Финальный релоад
    await run_command(f"docker exec {NGINX_CONTAINER_NAME} nginx -s reload")
    
    request.session["messages"] = [f"Success: Certificate issued and HTTPS enabled for {domain}!"]
    return RedirectResponse("/", status_code=302)

@app.post("/nginx/reload")
async def nginx_reload(request: Request, user: str = Depends(require_auth)):
    code, out, err = await run_command(f"docker exec {NGINX_CONTAINER_NAME} nginx -s reload")
    if code == 0:
        request.session["messages"] = ["Success: Nginx Reloaded"]
    else:
        request.session["messages"] = [f"Error: {err}"]
    return RedirectResponse("/", status_code=302)

@app.post("/nginx/test")
async def nginx_test(request: Request, user: str = Depends(require_auth)):
    code, out, err = await run_command(f"docker exec {NGINX_CONTAINER_NAME} nginx -t")
    if code == 0:
        request.session["messages"] = ["Success: Syntax OK"]
    else:
        request.session["messages"] = [f"Syntax Error: {err}"]
    return RedirectResponse("/", status_code=302)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=1337)
