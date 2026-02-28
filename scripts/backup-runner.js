require("./load-env");

const { backupSettings, copyVisibleBackup, executeBackup, pruneLocalBackups, writeManifest } = require("./backup-core");

const fullIntervalMinutes = Math.max(1, Number(process.env.BACKUP_FULL_INTERVAL_MINUTES || 360));
const logIntervalMinutes = Math.max(1, Number(process.env.BACKUP_LOG_INTERVAL_MINUTES || 15));
const enableLogBackups = String(process.env.BACKUP_ENABLE_LOG || "false").toLowerCase() === "true";

let fullRunning = false;
let logRunning = false;

async function runFullBackup() {
  if (fullRunning) return;
  fullRunning = true;

  try {
    const settings = backupSettings("full");
    console.log("[backup-daemon] full backup ->", settings.sqlPath);
    await executeBackup("full");

    const copyResult = copyVisibleBackup(settings);
    const removed = pruneLocalBackups(settings);
    const manifestPath = writeManifest({
      kind: "full",
      sqlPath: settings.sqlPath,
      localPath: copyResult.copied ? copyResult.localPath : null,
      removed,
      createdAt: new Date().toISOString()
    });

    if (!copyResult.copied) {
      console.warn("[backup-daemon] SQL backup created but not visible from app host:", settings.sqlPath);
    }

    console.log("[backup-daemon] full backup completed");
    console.log("[backup-daemon] manifest:", manifestPath);
  } catch (error) {
    console.error("[backup-daemon] full backup failed:", error.message);
  } finally {
    fullRunning = false;
  }
}

async function runLogBackup() {
  if (!enableLogBackups || logRunning) return;
  logRunning = true;

  try {
    const settings = backupSettings("log");
    console.log("[backup-daemon] log backup ->", settings.sqlPath);
    await executeBackup("log");

    const copyResult = copyVisibleBackup(settings);
    const removed = pruneLocalBackups(settings);
    const manifestPath = writeManifest({
      kind: "log",
      sqlPath: settings.sqlPath,
      localPath: copyResult.copied ? copyResult.localPath : null,
      removed,
      createdAt: new Date().toISOString()
    });

    if (!copyResult.copied) {
      console.warn("[backup-daemon] SQL log backup created but not visible from app host:", settings.sqlPath);
    }

    console.log("[backup-daemon] log backup completed");
    console.log("[backup-daemon] manifest:", manifestPath);
  } catch (error) {
    console.error("[backup-daemon] log backup failed:", error.message);
  } finally {
    logRunning = false;
  }
}

async function main() {
  console.log("[backup-daemon] started");
  console.log("[backup-daemon] full interval minutes:", fullIntervalMinutes);
  console.log("[backup-daemon] log interval minutes:", enableLogBackups ? logIntervalMinutes : "disabled");

  await runFullBackup();

  setInterval(() => {
    runFullBackup().catch((error) => {
      console.error("[backup-daemon] full interval failed:", error.message);
    });
  }, fullIntervalMinutes * 60 * 1000);

  if (enableLogBackups) {
    setInterval(() => {
      runLogBackup().catch((error) => {
        console.error("[backup-daemon] log interval failed:", error.message);
      });
    }, logIntervalMinutes * 60 * 1000);
  }
}

main().catch((error) => {
  console.error("[backup-daemon] fatal:", error.message);
  process.exit(1);
});
