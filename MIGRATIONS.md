# Migrations Runbook

This project uses Alembic for DB schema changes.

## Current flow

- Docker app startup runs:
  - `alembic upgrade head`
  - then starts `uvicorn`
- If migrations fail, app container retries and does not start serving traffic.

## Files

- Alembic config: `alembic.ini`
- Env: `alembic/env.py`
- Revisions: `alembic/versions/*.py`

## Standard deploy (Ubuntu + Docker Compose)

Run from project root:

```bash
git pull
docker compose up -d --build
docker compose logs --tail=120 app
```

## Manual migration (if needed)

```bash
docker compose run --rm --no-deps app alembic upgrade head
```

Check current revision:

```bash
docker compose run --rm --no-deps app alembic current
docker compose run --rm --no-deps app alembic heads
```

## Rollback (last revision)

```bash
docker compose run --rm --no-deps app alembic downgrade -1
```

Then restart app:

```bash
docker compose up -d --build
```

## Creating a new migration

Inside the project environment:

```bash
alembic revision -m "short_description"
```

Then implement `upgrade()`/`downgrade()` manually.

Important:
- Keep `revision` value length `<= 32` chars (PostgreSQL `alembic_version.version_num` limit).
- Prefer additive / idempotent SQL where possible.
- For data migrations, make steps deterministic and re-runnable.

## Troubleshooting

### `Command 'alembic' not found`
Use project context, not OS package:

```bash
docker compose run --rm --no-deps app alembic upgrade head
```

### `value too long for type character varying(32)` in `alembic_version`
Migration `revision` string is too long. Shorten `revision` in that migration file and rerun.

### App fails with "Database schema is not initialized. Run 'alembic upgrade head'."
Run:

```bash
docker compose run --rm --no-deps app alembic upgrade head
docker compose up -d --build
```

### Local changes block `git pull`
If server has uncommitted local edits:

```bash
git stash push -m "server-local"
git pull
git stash pop
```

