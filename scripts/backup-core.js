const fs = require("fs");
const path = require("path");
const sql = require("mssql");

function stamp() {
  const now = new Date();
  const pad = (value) => String(value).padStart(2, "0");
  return [
    now.getUTCFullYear(),
    pad(now.getUTCMonth() + 1),
    pad(now.getUTCDate()),
    pad(now.getUTCHours()),
    pad(now.getUTCMinutes()),
    pad(now.getUTCSeconds())
  ].join("");
}

function baseConfig(database) {
  return {
    user: process.env.DB_USER || "SA",
    password: process.env.DB_PASSWORD || "YourStrong!Passw0rd",
    server: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT || 1433),
    database,
    options: {
      encrypt: true,
      trustServerCertificate: true
    },
    pool: {
      max: 3,
      min: 0,
      idleTimeoutMillis: 30000
    }
  };
}

function backupSettings(kind) {
  const dbName = process.env.DB_NAME || "vs_business";
  const backupDir = process.env.BACKUP_DIR || "/var/opt/mssql/backup";
  const prefix = kind === "log" ? "log" : "full";
  const fallbackName = `${dbName}_${prefix}_${stamp()}.${kind === "log" ? "trn" : "bak"}`;
  const targetPath = kind === "log" ? process.env.BACKUP_LOG_FILE : process.env.BACKUP_FILE;
  const sqlPath = targetPath || path.join(backupDir, fallbackName);
  const localDir = path.resolve(__dirname, "..", "backups");
  const localPath = path.join(localDir, path.basename(sqlPath));

  return {
    dbName,
    kind,
    sqlPath,
    localDir,
    localPath,
    retentionCount: Math.max(1, Number(process.env.BACKUP_RETENTION_COUNT || 20)),
    retentionDays: Math.max(1, Number(process.env.BACKUP_RETENTION_DAYS || 14))
  };
}

async function executeBackup(kind) {
  const settings = backupSettings(kind);
  const pool = await new sql.ConnectionPool(baseConfig("master")).connect();
  const statement = kind === "log"
    ? `BACKUP LOG [${settings.dbName}] TO DISK = @path WITH COMPRESSION, INIT, STATS = 10;`
    : `BACKUP DATABASE [${settings.dbName}] TO DISK = @path WITH COPY_ONLY, COMPRESSION, INIT, STATS = 10;`;

  await pool.request().input("path", sql.NVarChar(4000), settings.sqlPath).query(statement);
  await pool.close();
  return settings;
}

function copyVisibleBackup(settings) {
  if (!fs.existsSync(settings.sqlPath)) {
    return { copied: false, localPath: settings.localPath };
  }

  fs.mkdirSync(settings.localDir, { recursive: true });
  fs.copyFileSync(settings.sqlPath, settings.localPath);
  return { copied: true, localPath: settings.localPath };
}

function writeManifest(entry) {
  const manifestPath = path.join(path.resolve(__dirname, "..", "backups"), "latest.json");
  fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
  fs.writeFileSync(manifestPath, JSON.stringify(entry, null, 2));
  return manifestPath;
}

function pruneLocalBackups(settings) {
  if (!fs.existsSync(settings.localDir)) return [];

  const now = Date.now();
  const maxAgeMs = settings.retentionDays * 24 * 60 * 60 * 1000;
  const files = fs.readdirSync(settings.localDir)
    .filter((name) => {
      if (settings.kind === "log") return name.endsWith(".trn");
      return name.endsWith(".bak");
    })
    .map((name) => {
      const fullPath = path.join(settings.localDir, name);
      const stat = fs.statSync(fullPath);
      return { name, fullPath, mtimeMs: stat.mtimeMs };
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);

  const removed = [];
  files.forEach((file, index) => {
    const expired = now - file.mtimeMs > maxAgeMs;
    const overflow = index >= settings.retentionCount;
    if (!expired && !overflow) return;
    fs.unlinkSync(file.fullPath);
    removed.push(file.fullPath);
  });

  return removed;
}

module.exports = {
  backupSettings,
  copyVisibleBackup,
  executeBackup,
  pruneLocalBackups,
  writeManifest
};
