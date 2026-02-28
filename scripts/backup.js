require("./load-env");

const { backupSettings, executeBackup, writeManifest } = require("./backup-core");

async function main() {
  const settings = backupSettings("full");
  console.log("[backup] target file:", settings.sqlPath);
  await executeBackup("full");
  const manifestPath = writeManifest({
    kind: "full",
    sqlPath: settings.sqlPath,
    localPath: null,
    createdAt: new Date().toISOString()
  });
  console.log("[backup] completed");
  console.log("[backup] manifest:", manifestPath);
}

main().catch((err) => {
  console.error("[backup] failed:", err.message);
  console.error("Hint: ensure BACKUP_DIR exists and SQL Server service account can write to it.");
  process.exit(1);
});
