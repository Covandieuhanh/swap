/* Initialize empty VoucherSwap schema and seed minimal data.
 * - Creates database if missing
 * - Applies schema (idempotent)
 * - Seeds admin user/role (idempotent)
 */

require("./load-env");

const fs = require("fs");
const path = require("path");
const sql = require("mssql");

async function main() {
  const dbName = process.env.DB_NAME || "vs_business";

  const baseConfig = {
    user: process.env.DB_USER || "SA",
    password: process.env.DB_PASSWORD || "YourStrong!Passw0rd",
    server: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT || 1433),
    options: { encrypt: true, trustServerCertificate: true },
    pool: { max: 10, min: 0, idleTimeoutMillis: 30000 }
  };

  // 1) Ensure database exists (connect to master)
  console.log(`[db-init] Connecting to master on ${baseConfig.server}:${baseConfig.port}...`);
  const masterPool = await new sql.ConnectionPool({ ...baseConfig, database: "master" }).connect();
  const dbExists = await masterPool
    .request()
    .input("dbName", sql.NVarChar(256), dbName)
    .query("SELECT 1 AS ok FROM sys.databases WHERE name = @dbName");
  if (!dbExists.recordset.length) {
    console.log(`[db-init] Creating database ${dbName} ...`);
    await masterPool.request().query(`CREATE DATABASE [${dbName}] COLLATE Latin1_General_100_CI_AS_SC`);
  } else {
    console.log(`[db-init] Database ${dbName} already exists`);
  }
  await masterPool.close();

  // 2) Apply schema + seed
  const pool = await new sql.ConnectionPool({ ...baseConfig, database: dbName }).connect();
  const schemaPath = path.resolve(__dirname, "..", "ops", "sql", "schema.sql");
  const seedPath = path.resolve(__dirname, "..", "ops", "sql", "seed.sql");
  const schemaSql = fs.readFileSync(schemaPath, "utf8");
  const seedSql = fs.readFileSync(seedPath, "utf8");

  console.log("[db-init] Applying schema...");
  await pool.request().batch(schemaSql);

  console.log("[db-init] Seeding minimal data...");
  await pool.request().batch(seedSql);

  await pool.close();
  console.log("[db-init] Done. Admin login: admin@example.com / Admin123!");
}

main().catch((err) => {
  console.error("[db-init] Failed:", err);
  process.exit(1);
});

