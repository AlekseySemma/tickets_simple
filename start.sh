#!/usr/bin/env bash
set -euo pipefail

echo "Applying database migrations..."
attempt=1
max_attempts=20

until alembic upgrade head; do
  if [ "$attempt" -ge "$max_attempts" ]; then
    echo "Migration failed after ${max_attempts} attempts"
    exit 1
  fi
  echo "Migration attempt ${attempt} failed, retrying in 3s..."
  attempt=$((attempt + 1))
  sleep 3
done

echo "Starting application..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
