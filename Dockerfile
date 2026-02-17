FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# системные пакеты (минимум; можно расширить если понадобятся зависимости)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
 && rm -rf /var/lib/apt/lists/*

# зависимости Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# код приложения
COPY . .

# если у тебя другой модуль/приложение — поменяем ниже команду
CMD ["bash", "-lc", "uvicorn main.py --host 0.0.0.0 --port 8000"]
