#!/usr/bin/env bash
set -euo pipefail

echo "[deploy] installing deps..."
npm ci

echo "[deploy] verify config and DB..."
npm run check:syntax
npm run health

echo "[deploy] starting server..."
NODE_ENV=production node server.js
