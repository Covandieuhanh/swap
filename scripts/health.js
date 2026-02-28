require("./load-env");

// Quick health check: DB connection + Users row count
const sql = require("mssql");

const dbConfig = {
  user: process.env.DB_USER || "SA",
  password: process.env.DB_PASSWORD || "YourStrong!Passw0rd",
  server: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 1433),
  database: process.env.DB_NAME || "vs_business",
  options: { encrypt: true, trustServerCertificate: true },
  pool: { max: 5, min: 0, idleTimeoutMillis: 30000 }
};

async function main() {
  console.log("[health] connecting to DB...");
  const pool = await new sql.ConnectionPool(dbConfig).connect();
  const ping = await pool.request().query("SELECT 1 AS ok");
  const users = await pool.request().query("SELECT COUNT(*) AS total FROM dbo.Users");
  console.log("[health] DB ok:", ping.recordset[0].ok === 1);
  console.log("[health] Users total:", users.recordset[0].total);
  await pool.close();
}

main().catch((err) => {
  console.error("[health] failed:", err.message);
  process.exit(1);
});
