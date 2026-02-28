# VoucherSwap Local One-Page

Serve the restored `vs_business` database through a Node app that keeps the original front-end flow working without the old external APIs.

## Quick start
```bash
cp .env.example .env
npm install
npm run verify
npm start
```

## GitHub as source of truth
- This repo is ready to push directly to GitHub.
- `.gitignore` excludes `.env`, `node_modules`, logs, local backups, and generated backup metadata.
- GitHub Actions runs `npm run check:syntax` on every push and pull request.
- The repo stays server-neutral: Railway files are included, but they do not block Docker, VPS, PM2, or other Node hosts.

## Deploy options

### Generic Node host
```bash
npm ci
npm start
```

### Docker host
```bash
docker build -t voucherswap .
docker run --env-file .env -p 8080:8080 voucherswap
```

### Docker Compose
```bash
docker compose up -d --build
```
This starts:
- `app`: the web/API process
- `backup`: a long-running backup worker using `npm run backup:daemon`

### PM2 / VPS
```bash
pm2 start ecosystem.config.js
```

### systemd / Linux server
Service templates are included:
- `ops/systemd/voucherswap-app.service`
- `ops/systemd/voucherswap-backup.service`

### Railway
- `railway.json` sets `npm start` and `/local-api/health`
- `nixpacks.toml` pins Node 20 and `npm ci`
- Required Railway variables: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `JWT_SECRET`, `ALLOW_ORIGIN`

## Backup model
- `npm run backup` creates a full SQL Server backup on the SQL host path.
- `npm run backup:log` creates a transaction-log backup when SQL Server recovery mode supports it.
- `npm run backup:local` creates a full backup and copies it into `./backups` when the SQL backup path is visible from the app host.
- `npm run backup:daemon` starts a 24/7 worker:
  - runs a full backup immediately on startup
  - repeats full backups every `BACKUP_FULL_INTERVAL_MINUTES`
  - optionally runs log backups every `BACKUP_LOG_INTERVAL_MINUTES` when `BACKUP_ENABLE_LOG=true`
  - writes `backups/latest.json`
  - prunes local copies using `BACKUP_RETENTION_COUNT` and `BACKUP_RETENTION_DAYS`

## Important backup constraint
SQL Server writes `.bak` and `.trn` files on the SQL Server machine, not automatically on the app host. For fully restorable off-host copies, one of these must be true:
- `BACKUP_DIR` points to a path the SQL Server host and your app host both see
- SQL Server runs on the same host
- SQL Server runs in Docker and you copy backups out with `docker cp`

## Scripts
- `npm run check:syntax`
- `npm run health`
- `npm run smoke`
- `npm run backup`
- `npm run backup:log`
- `npm run backup:local`
- `npm run backup:daemon`
- `npm run verify`
- `npm run serve`

## Production notes
- `server.js` fails fast in production if required DB or JWT variables are missing.
- Use a strong `JWT_SECRET`; do not keep the local default.
- Restrict SQL Server network access to known app hosts.
- Set `ALLOW_ORIGIN` to your public domain once the site is live.
