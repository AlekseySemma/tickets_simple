# AdminVPS Migration Runbook

This project is ready to run on a regular Ubuntu VPS with Docker Compose.
The application server can move to AdminVPS while object storage remains on Beget S3.

## What must be transferred

- Project source code
- Production `.env`
- `private_key.pem`
- `firebase-service-account.json` if Android/mobile push is used
- PostgreSQL data from the old server
- DNS for the main domain

If `STORAGE_BACKEND=s3`, the application files already stored in Beget S3 do not need to be copied to AdminVPS.

## Recommended target layout

```bash
/opt/tickets_simple
```

## 1. Prepare the new AdminVPS server

Install Docker, Compose plugin, nginx, and Certbot:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin nginx certbot python3-certbot-nginx
sudo systemctl enable --now docker
```

Clone the project and place the secret files:

```bash
sudo mkdir -p /opt/tickets_simple
sudo chown $USER:$USER /opt/tickets_simple
cd /opt/tickets_simple
git clone <your-repo-url> .
```

Then place:

- `.env`
- `private_key.pem`
- `firebase-service-account.json` if used

## 2. Fill production `.env`

Minimum production values:

```env
POSTGRES_DB=tickets
POSTGRES_USER=tickets
POSTGRES_PASSWORD=replace-with-strong-password

JWT_SECRET=replace-with-long-random-secret-at-least-32-chars
AUTH_COOKIE_DOMAIN=servora.ru

STORAGE_BACKEND=s3
S3_ENDPOINT_URL=https://s3.ru1.storage.beget.cloud
S3_BUCKET=your-existing-bucket
S3_ACCESS_KEY=your-existing-key
S3_SECRET_KEY=your-existing-secret
S3_REGION=ru1
S3_ADDRESSING_STYLE=path
S3_PRESIGNED_TTL_SECONDS=3600
```

Notes:

- Set `AUTH_COOKIE_DOMAIN` to the root domain if the app works on a subdomain such as `desk.servora.ru`.
- If the project is opened only on one exact host and shared cookies are not needed, `AUTH_COOKIE_DOMAIN` may be left empty.
- Keep the existing Beget S3 credentials unchanged.

## 3. Export PostgreSQL from the old Beget server

Run on the old server:

```bash
cd /path/to/project
docker compose exec -T db pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" > tickets.sql
```

If the old deployment does not keep `POSTGRES_USER` and `POSTGRES_DB` in `.env`, use the actual values from the old container.

Copy the dump to AdminVPS:

```bash
scp tickets.sql user@NEW_SERVER_IP:/opt/tickets_simple/tickets.sql
```

## 4. Start containers on AdminVPS

Run on the new server:

```bash
cd /opt/tickets_simple
docker compose up -d --build
docker compose logs --tail=120 app
```

Restore the dump:

```bash
cd /opt/tickets_simple
cat tickets.sql | docker compose exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
docker compose restart app
docker compose logs --tail=120 app
```

The app container runs Alembic migrations automatically on startup.

## 5. Configure nginx

Use the example file:

- `deploy/adminvps/nginx.servora.conf.example`

Copy it to `/etc/nginx/sites-available/servora.conf`, replace domain names, then enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/servora.conf /etc/nginx/sites-enabled/servora.conf
sudo nginx -t
sudo systemctl reload nginx
```

## 6. Issue TLS certificate

After DNS points to AdminVPS:

```bash
sudo certbot --nginx -d servora.ru -d desk.servora.ru
```

## 7. Switch DNS

Move the A record for the production domain or subdomain to the new AdminVPS IP.

Recommended order:

1. Lower DNS TTL on the old provider before the move.
2. Bring up the app on AdminVPS and test it by IP or temporary host entry.
3. Update DNS.
4. Verify login, file downloads, uploads, email links, and Android push registration.

## 8. Smoke checks after cutover

```bash
curl -I https://your-domain
docker compose ps
docker compose logs --tail=200 app
docker compose logs --tail=100 db
```

Check manually:

- Web login/logout
- Existing ticket attachments open correctly
- New uploads are stored in Beget S3
- Email verification and password reset links use the correct HTTPS domain
- Mobile push registration still works if Android app is used

## Rollback

If needed, point DNS back to the old server and stop using the new one until the issue is fixed.
Do not delete the old Beget server until the AdminVPS instance has passed production checks.
