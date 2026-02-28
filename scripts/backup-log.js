require("./load-env");

const { backupSettings, executeBackup, writeManifest } = require("./backup-core");

async function main() {
  const settings = backupSettings("log");
  console.log("[backup-log] target file:", settings.sqlPath);
  await executeBackup("log");
  const manifestPath = writeManifest({
    kind: "log",
    sqlPath: settings.sqlPath,
    localPath: null,
    createdAt: new Date().toISOString()
  });
  console.log("[backup-log] completed");
  console.log("[backup-log] manifest:", manifestPath);
}

main().catch((err) => {
  console.error("[backup-log] failed:", err.message);
  console.error("Hint: SQL Server must use a recovery model that supports BACKUP LOG.");
  process.exit(1);
});
