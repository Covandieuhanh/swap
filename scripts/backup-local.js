require("./load-env");

const {
  backupSettings,
  copyVisibleBackup,
  executeBackup,
  pruneLocalBackups,
  writeManifest
} = require("./backup-core");

async function main() {
  const settings = backupSettings("full");
  console.log("[backup-local] target:", settings.sqlPath);

  await executeBackup("full");
  console.log("[backup-local] backup finished");

  const copyResult = copyVisibleBackup(settings);
  if (!copyResult.copied) {
    console.warn("[backup-local] WARNING: backup file not visible at", settings.sqlPath, "- cannot copy to repo.");
    console.warn("[backup-local] Backup likely inside SQL Server environment. If SQL runs in Docker, run:");
    console.warn("  docker cp <mssql-container>:" + settings.sqlPath + " ./backups/");
  }

  const removed = pruneLocalBackups(settings);
  const manifestPath = writeManifest({
    kind: "full",
    sqlPath: settings.sqlPath,
    localPath: copyResult.copied ? copyResult.localPath : null,
    removed,
    createdAt: new Date().toISOString()
  });

  console.log("[backup-local] manifest:", manifestPath);
  try {
    const fs = require("fs");
    const size = fs.statSync(copyResult.copied ? copyResult.localPath : settings.sqlPath).size;
    console.log("[backup-local] size bytes:", size);
  } catch (e) {
    // Backup may only exist inside SQL Server's filesystem.
  }
}

main().catch((err) => {
  console.error("[backup-local] failed:", err.message);
  process.exit(1);
});
