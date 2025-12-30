FROM python:3.12-slim

WORKDIR /app

# Устанавливаем Docker CLI и необходимые утилиты
RUN apt-get update && \
    apt-get install -y docker.io curl && \
    rm -rf /var/lib/apt/lists/*

# Устанавливаем uv
RUN pip install uv

COPY pyproject.toml uv.lock ./

# Если uv.lock еще нет, создаем пустышки или пропускаем sync
# (для первого запуска можно использовать pip install -r requirements.txt если он есть)
# Но согласно вашему файлу:
RUN uv sync || true

COPY . .

EXPOSE 8000

CMD ["uv", "run", "main.py"]
