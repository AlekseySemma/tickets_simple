# tickets_simple

Сервис для управления заявками (FastAPI + PostgreSQL + Docker Compose).

## Быстрый старт (Docker Compose)

Из корня проекта:

```bash
docker compose up -d --build
docker compose logs --tail=120 app
```

## Обязательные переменные окружения

В `.env` должны быть заданы минимум:

```env
JWT_SECRET=your-secret-at-least-32-chars
```

Для push-уведомлений также:

```env
VAPID_PUBLIC_KEY=...
VAPID_SUBJECT=mailto:admin@example.com
```

`VAPID_PRIVATE_KEY` используется из `private_key.pem` (см. `docker-compose.yml`).

## Migrations

Проект использует Alembic. Полный runbook:

- `MIGRATIONS.md`

Коротко:

```bash
docker compose run --rm --no-deps app alembic upgrade head
```

## Деплой (Ubuntu)

```bash
git pull
docker compose up -d --build
docker compose logs --tail=120 app
```

