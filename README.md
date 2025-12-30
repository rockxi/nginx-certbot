# UINX 

## UI+WEB service for Nginx administration with fast SSL/TLS certificates issue.

Nginx + Certbot + docker UI-configure compose for quick and easy configuration of reverse proxy and ssl certificates.

https://github.com/user-attachments/assets/a2300450-fff8-47b8-b6af-14d0a05b60b5

**1) Preload and write envs**
```bash
git clone https://github.com/rockxi/nginx-certbot && cd nginx-certbot
cat >> .env << EOF
ADMIN_USERNAME=admin      # !!! REPLACE WITH YOUR SECRET VALUES !!!
ADMIN_PASSWORD=password
EOF
```

**2) Start**
```bash
docker-compose up --build -d
```

**3) Go to UI** - `yourdomain:1337` or `localhost:1337` (if you starts localy)

**4) Enjoy!**

