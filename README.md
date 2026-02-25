# tickets_simple

Сервис для управления заявками (FastAPI + PostgreSQL + Docker Compose).

## Contents

- [Overview](#overview)
- [Quick Start (Docker Compose)](#quick-start-docker-compose)
- [Environment Variables](#environment-variables)
- [Migrations](#migrations)
- [Deploy (Ubuntu)](#deploy-ubuntu)

## Overview

`tickets_simple` — веб-сервис для работы с заявками, пользователями, проектами и вложениями.

## Quick Start (Docker Compose)

Из корня проекта:

```bash
docker compose up -d --build
docker compose logs --tail=120 app
```

## Environment Variables

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

## Deploy (Ubuntu)

```bash
git pull
docker compose up -d --build
docker compose logs --tail=120 app
```

## Org Structure Feature Flag

Set in `.env` to control visibility of upcoming org-structure mode in UI:

```env
ORG_STRUCTURE_V2_ENABLED=0
```
