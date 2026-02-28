require("./load-env");

// End-to-end smoke test: register temp user via API, login, fetch wallet, then delete user in DB.
const crypto = require("crypto");
const sql = require("mssql");
const fetch = global.fetch;

const base = process.env.BASE_URL || "http://localhost:8080";
const apiBase = `${base.replace(/\/+$/, "")}/local-api`;
const identityBase = `${base.replace(/\/+$/, "")}/local-identity`;

const dbConfig = {
  user: process.env.DB_USER || "SA",
  password: process.env.DB_PASSWORD || "YourStrong!Passw0rd",
  server: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 1433),
  database: process.env.DB_NAME || "vs_business",
  options: { encrypt: true, trustServerCertificate: true },
  pool: { max: 5, min: 0, idleTimeoutMillis: 30000 }
};

async function register(email, password) {
  const body = { user: { email, userName: email, phoneNumber: "", fullName: email, referenceEmail: "" }, password };
  const res = await fetch(`${apiBase}/users/Register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(`Register failed ${res.status}`);
  return res.json();
}

async function login(email, password) {
  const form = new URLSearchParams();
  form.set("UserName", email);
  form.set("Password", password);
  form.set("grant_type", "password");
  const res = await fetch(`${identityBase}/connect/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString()
  });
  if (!res.ok) throw new Error(`Login failed ${res.status}`);
  const json = await res.json();
  if (!json.access_token) throw new Error("Missing access_token");
  return json.access_token;
}

async function wallet(token) {
  const res = await fetch(`${apiBase}/users/GetUserInfo`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!res.ok) throw new Error(`GetUserInfo failed ${res.status}`);
  return res.json();
}

async function deleteUser(email) {
  const pool = await new sql.ConnectionPool(dbConfig).connect();
  await pool
    .request()
    .input("email", sql.NVarChar(256), email)
    .query("DELETE FROM dbo.Users WHERE UPPER(ISNULL(Email,'')) = UPPER(@email) OR UPPER(ISNULL(NormalizedEmail,'')) = UPPER(@email)");
  await pool.close();
}

async function main() {
  const email = `smoke_${Date.now()}_${crypto.randomUUID().slice(0, 6)}@example.com`;
  const password = "P@ssw0rd!";
  console.log("[smoke] base:", base);
  console.log("[smoke] register:", email);
  await register(email, password);
  const token = await login(email, password);
  console.log("[smoke] token ok");
  const info = await wallet(token);
  console.log("[smoke] wallet ok:", info && info.result ? info.result.email || info.result.Email : "unknown");
  await deleteUser(email);
  console.log("[smoke] cleanup done");
}

main().catch((err) => {
  console.error("[smoke] failed:", err.message);
  process.exit(1);
});
