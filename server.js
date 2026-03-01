require("./scripts/load-env");

const crypto = require("crypto");
const path = require("path");

const express = require("express");
const jwt = require("jsonwebtoken");
const sql = require("mssql");

const app = express();

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "127.0.0.1";
const JWT_SECRET = process.env.JWT_SECRET || "voucherswap-local-secret";
const TOKEN_EXPIRES_SEC = Number(process.env.TOKEN_EXPIRES_SEC || 86400);
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || "*";
const IS_PRODUCTION = process.env.NODE_ENV === "production" || Boolean(process.env.RAILWAY_ENVIRONMENT);
const EMAIL_VERIFICATION_REQUIRED = process.env.EMAIL_VERIFICATION_REQUIRED
  ? !/^false$/i.test(String(process.env.EMAIL_VERIFICATION_REQUIRED))
  : IS_PRODUCTION;
const EMAIL_VERIFICATION_DEBUG = process.env.EMAIL_VERIFICATION_DEBUG
  ? !/^false$/i.test(String(process.env.EMAIL_VERIFICATION_DEBUG))
  : !IS_PRODUCTION;
const EMAIL_VERIFICATION_TTL_MINUTES = Math.max(5, Number(process.env.EMAIL_VERIFICATION_TTL_MINUTES || 30));
const EMAIL_VERIFICATION_PROVIDER = process.env.EMAIL_VERIFICATION_PROVIDER || "VoucherSwapLocal";
const EMAIL_VERIFICATION_TOKEN_NAME = process.env.EMAIL_VERIFICATION_TOKEN_NAME || "EmailVerification";
const EMAIL_DELIVERY_MODE = String(process.env.EMAIL_DELIVERY_MODE || (EMAIL_VERIFICATION_DEBUG ? "debug" : "disabled")).toLowerCase();
const EMAIL_DELIVERY_WEBHOOK_URL = process.env.EMAIL_DELIVERY_WEBHOOK_URL || "";
const APP_PUBLIC_URL = process.env.APP_PUBLIC_URL || "";
const ALLOW_LOCAL_REGISTER = /^true$/i.test(String(process.env.ALLOW_LOCAL_REGISTER || "false"));

function assertProductionEnv() {
  if (!IS_PRODUCTION) return;

  const required = ["DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME", "JWT_SECRET"];
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(`Missing required production env vars: ${missing.join(", ")}`);
  }

  if (JWT_SECRET === "voucherswap-local-secret") {
    throw new Error("JWT_SECRET must be overridden in production");
  }
}

assertProductionEnv();

const dbConfig = {
  user: process.env.DB_USER || "SA",
  password: process.env.DB_PASSWORD || "YourStrong!Passw0rd",
  server: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 1433),
  database: process.env.DB_NAME || "vs_business",
  options: {
    encrypt: true,
    trustServerCertificate: true
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000
  }
};

let poolPromise;
function getPool() {
  if (!poolPromise) {
    poolPromise = new sql.ConnectionPool(dbConfig).connect();
  }
  return poolPromise;
}

function normalize(input) {
  return String(input || "").trim().toUpperCase();
}

function getDigestByPrf(prf) {
  if (prf === 0) return "sha1";
  if (prf === 1) return "sha256";
  if (prf === 2) return "sha512";
  return null;
}

function verifyAspNetIdentityHash(hash, password) {
  try {
    if (!hash || !password) return false;
    const decoded = Buffer.from(hash, "base64");
    if (!decoded || decoded.length < 13) return false;
    if (decoded[0] !== 0x01) return false;

    const prf = decoded.readUInt32BE(1);
    const iterCount = decoded.readUInt32BE(5);
    const saltLength = decoded.readUInt32BE(9);
    if (saltLength <= 0 || decoded.length < 13 + saltLength) return false;

    const digest = getDigestByPrf(prf);
    if (!digest) return false;

    const salt = decoded.slice(13, 13 + saltLength);
    const expectedSubkey = decoded.slice(13 + saltLength);
    const actualSubkey = crypto.pbkdf2Sync(
      Buffer.from(password, "utf8"),
      salt,
      iterCount,
      expectedSubkey.length,
      digest
    );
    return crypto.timingSafeEqual(expectedSubkey, actualSubkey);
  } catch (_err) {
    return false;
  }
}

function hashAspNetIdentityV3(password) {
  const formatMarker = 0x01;
  const prf = 1; // HMACSHA256
  const iterCount = 10000;
  const salt = crypto.randomBytes(16);
  const subkey = crypto.pbkdf2Sync(Buffer.from(password, "utf8"), salt, iterCount, 32, "sha256");

  const output = Buffer.alloc(13 + salt.length + subkey.length);
  output[0] = formatMarker;
  output.writeUInt32BE(prf, 1);
  output.writeUInt32BE(iterCount, 5);
  output.writeUInt32BE(salt.length, 9);
  salt.copy(output, 13);
  subkey.copy(output, 13 + salt.length);
  return output.toString("base64");
}

async function getUserByLogin(loginValue) {
  const lookup = normalize(loginValue);
  const pool = await getPool();
  const result = await pool
    .request()
    .input("lookup", sql.NVarChar(256), lookup)
    .query(`
      SELECT TOP 1
        Id,
        UserName,
        Email,
        EmailConfirmed,
        PasswordHash,
        ConsumptionBalance,
        AffiliateBalance,
        AccumulateBalance,
        SavingBalance,
        BusinessBalance,
        InvestBalance
      FROM dbo.Users
      WHERE UPPER(ISNULL(Email, '')) = @lookup
         OR UPPER(ISNULL(UserName, '')) = @lookup
         OR UPPER(ISNULL(NormalizedEmail, '')) = @lookup
         OR UPPER(ISNULL(NormalizedUserName, '')) = @lookup
    `);
  return result.recordset[0] || null;
}

async function getUserById(id) {
  const pool = await getPool();
  const result = await pool
    .request()
    .input("id", sql.UniqueIdentifier, id)
    .query(`
      SELECT TOP 1
        Id,
        UserName,
        Email,
        EmailConfirmed,
        ConsumptionBalance,
        AffiliateBalance,
        AccumulateBalance,
        SavingBalance,
        BusinessBalance,
        InvestBalance
      FROM dbo.Users
      WHERE Id = @id
    `);
  return result.recordset[0] || null;
}

function toNumber(v) {
  if (v === null || v === undefined) return 0;
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function toAddress(id) {
  return String(id || "").trim().toLowerCase();
}

function buildUserResult(user) {
  return {
    id: String(user.Id),
    userName: user.UserName || "",
    email: user.Email || "",
    consumptionBalance: toNumber(user.ConsumptionBalance),
    affiliateBalance: toNumber(user.AffiliateBalance),
    accumulateBalance: toNumber(user.AccumulateBalance),
    savingBalance: toNumber(user.SavingBalance),
    businessBalance: toNumber(user.BusinessBalance),
    investBalance: toNumber(user.InvestBalance),
    emailConfirmed: Boolean(user.EmailConfirmed),
    receiveAddress: toAddress(user.Id)
  };
}

async function getUserRoles(userId) {
  const pool = await getPool();
  const result = await pool
    .request()
    .input("userId", sql.UniqueIdentifier, userId)
    .query(`
      SELECT r.Id, r.Name, r.NormalizedName
      FROM dbo.UserRoles ur
      JOIN dbo.Roles r ON ur.RoleId = r.Id
      WHERE ur.UserId = @userId
    `);
  return result.recordset || [];
}

async function getUserWithRoles(userId) {
  const user = await getUserById(userId);
  if (!user) return null;
  const roles = await getUserRoles(userId);
  return { ...buildUserResult(user), roles };
}

function hasRole(roles, names = []) {
  if (!Array.isArray(roles) || !roles.length) return false;
  const lookup = roles.map((r) => String(r.Name || "").toUpperCase());
  return names.some((n) => lookup.includes(String(n || "").toUpperCase()));
}

function requireRoles(allowedRoles) {
  return async (req, res, next) => {
    try {
      const userId = req.auth?.sub;
      if (!userId) return res.status(401).json({ message: "Missing token user" });
      const roles = await getUserRoles(userId);
      req.auth.roles = roles;
      if (!hasRole(roles, allowedRoles)) {
        return res.status(403).json({ message: "Không đủ quyền" });
      }
      next();
    } catch (err) {
      return res.status(500).json({ message: err.message });
    }
  };
}

function toAssetUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  if (/^https?:\/\//i.test(raw)) return raw;
  return `https://voucherswap.net${raw.startsWith("/") ? "" : "/"}${raw}`;
}

function formatMoneyEn(amount) {
  return Number(amount || 0).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  });
}

function hashVerificationValue(value) {
  return crypto.createHash("sha256").update(String(value || ""), "utf8").digest("hex");
}

function generateVerificationCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function buildVerificationLink(email, code) {
  const base = String(APP_PUBLIC_URL || "").trim().replace(/\/+$/, "");
  if (!base) return "";
  const url = new URL(base);
  url.searchParams.set("verifyEmail", email);
  url.searchParams.set("verifyCode", code);
  return url.toString();
}

async function upsertUserToken(userId, loginProvider, name, value) {
  const pool = await getPool();
  await pool
    .request()
    .input("userId", sql.UniqueIdentifier, userId)
    .input("loginProvider", sql.NVarChar(450), loginProvider)
    .input("name", sql.NVarChar(450), name)
    .input("value", sql.NVarChar(sql.MAX), value)
    .query(`
      DELETE FROM dbo.UserTokens
      WHERE UserId = @userId AND LoginProvider = @loginProvider AND Name = @name;

      INSERT INTO dbo.UserTokens (UserId, LoginProvider, Name, Value)
      VALUES (@userId, @loginProvider, @name, @value);
    `);
}

async function getUserToken(userId, loginProvider, name) {
  const pool = await getPool();
  const result = await pool
    .request()
    .input("userId", sql.UniqueIdentifier, userId)
    .input("loginProvider", sql.NVarChar(450), loginProvider)
    .input("name", sql.NVarChar(450), name)
    .query(`
      SELECT TOP 1 UserId, LoginProvider, Name, Value
      FROM dbo.UserTokens
      WHERE UserId = @userId AND LoginProvider = @loginProvider AND Name = @name
    `);
  return result.recordset[0] || null;
}

async function deleteUserToken(userId, loginProvider, name) {
  const pool = await getPool();
  await pool
    .request()
    .input("userId", sql.UniqueIdentifier, userId)
    .input("loginProvider", sql.NVarChar(450), loginProvider)
    .input("name", sql.NVarChar(450), name)
    .query(`
      DELETE FROM dbo.UserTokens
      WHERE UserId = @userId AND LoginProvider = @loginProvider AND Name = @name
    `);
}

function parseVerificationPayload(value) {
  if (!value) return null;
  try {
    return JSON.parse(String(value));
  } catch (_err) {
    return null;
  }
}

async function issueEmailVerification(user) {
  const code = generateVerificationCode();
  const expiresAt = new Date(Date.now() + EMAIL_VERIFICATION_TTL_MINUTES * 60 * 1000).toISOString();
  const payload = {
    type: "email_verification",
    email: String(user.Email || "").trim().toLowerCase(),
    hash: hashVerificationValue(code),
    expiresAt,
    createdAt: new Date().toISOString()
  };

  await upsertUserToken(user.Id, EMAIL_VERIFICATION_PROVIDER, EMAIL_VERIFICATION_TOKEN_NAME, JSON.stringify(payload));

  const verificationLink = buildVerificationLink(payload.email, code);
  if (EMAIL_DELIVERY_MODE === "webhook" && EMAIL_DELIVERY_WEBHOOK_URL) {
    await fetch(EMAIL_DELIVERY_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kind: "email_verification",
        to: payload.email,
        code,
        expiresAt,
        verificationLink
      })
    });
  } else if (EMAIL_VERIFICATION_DEBUG || EMAIL_DELIVERY_MODE === "debug") {
    console.log(`[verification] email=${payload.email} code=${code} expiresAt=${expiresAt}`);
    if (verificationLink) {
      console.log(`[verification] link=${verificationLink}`);
    }
  }

  return {
    code,
    expiresAt,
    verificationLink
  };
}

function parsePositiveAmount(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount <= 0) return null;
  return Math.round(amount * 100) / 100;
}

function calcPercent(amount, percent) {
  const n = Number(amount);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.round(n * percent * 100) / 100;
}

function isGuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(value || "").trim());
}

function formatConsumptionHistoryRow(row) {
  return {
    id: row.Id,
    transactionHash: row.TransactionHash || "",
    addressFrom: row.AddressFrom || "",
    addressTo: row.AddressTo || "",
    amount: toNumber(row.Amount),
    type: row.Type,
    remark: row.Remark || "",
    dateCreated: row.DateCreated
  };
}

const walletHistoryTables = {
  consumption: "dbo.WalletConsumptionTransactions",
  affiliate: "dbo.WalletAffiliateTransactions",
  accumulate: "dbo.WalletAccumulateTransactions",
  saving: "dbo.WalletSavingTransactions",
  business: "dbo.WalletBusinessTransactions",
  invest: "dbo.WalletInvestTransactions"
};

function getWalletHistoryTable(walletType) {
  return walletHistoryTables[String(walletType || "").trim().toLowerCase()] || null;
}

async function getWalletHistory(walletType, appUserId, limit) {
  const tableName = getWalletHistoryTable(walletType);
  if (!tableName) return null;

  const result = await (await getPool())
    .request()
    .input("appUserId", sql.UniqueIdentifier, appUserId)
    .input("limit", sql.Int, limit)
    .query(`
      SELECT TOP (@limit)
        Id,
        TransactionHash,
        AddressFrom,
        AddressTo,
        Amount,
        Type,
        Remark,
        DateCreated
      FROM ${tableName}
      WHERE AppUserId = @appUserId
      ORDER BY DateCreated DESC, Id DESC
    `);

  return result.recordset.map(formatConsumptionHistoryRow);
}

function formatProjectRow(row) {
  return {
    id: row.Id,
    name: row.Name || "",
    description: row.Description || "",
    catalogName: row.CatalogName || "",
    type: row.Type,
    isSystem: Boolean(row.IsSystem),
    status: row.Status,
    investBalance: toNumber(row.InvestBalance),
    createdOn: row.CreatedOn
  };
}

function formatInvestPackageRow(row) {
  return {
    id: row.Id,
    name: row.Name || "",
    price: toNumber(row.Price),
    image: row.Image || "",
    imageUrl: toAssetUrl(row.Image),
    orderIndex: row.OrderIndex,
    status: row.Status
  };
}

function formatProjectInvestRow(row) {
  return {
    id: row.Id,
    projectId: row.ProjectId,
    projectName: row.ProjectName || "",
    amount: toNumber(row.Amount),
    remark: row.Remark || "",
    status: row.Status,
    investPackageId: row.InvestPackageId,
    packageName: row.PackageName || "",
    packagePrice: toNumber(row.PackagePrice),
    transactionHash: row.TransactionHash || "",
    createdOn: row.CreatedOn
  };
}

async function getInvestOverview(appUserId) {
  const pool = await getPool();

  const [projectsResult, packagesResult, summaryResult, investmentsResult] = await Promise.all([
    pool
      .request()
      .query(`
        SELECT
          p.Id,
          p.Name,
          p.Description,
          p.Type,
          p.IsSystem,
          p.Status,
          p.InvestBalance,
          p.CreatedOn,
          pc.Name AS CatalogName
        FROM dbo.Projects p
        LEFT JOIN dbo.ProjectCatalogs pc ON pc.Id = p.ProjectCatalogId
        WHERE ISNULL(p.Status, 0) = 1
        ORDER BY p.IsSystem DESC, p.Id ASC
      `),
    pool
      .request()
      .query(`
        SELECT
          Id,
          Name,
          Price,
          Image,
          OrderIndex,
          Status
        FROM dbo.InvestPackages
        WHERE ISNULL(Status, 0) = 1
        ORDER BY ISNULL(OrderIndex, 0) ASC, Id ASC
      `),
    pool
      .request()
      .input("appUserId", sql.UniqueIdentifier, appUserId)
      .query(`
        SELECT
          COUNT(*) AS InvestCount,
          ISNULL(SUM(Amount), 0) AS TotalInvested
        FROM dbo.ProjectInvests
        WHERE AppUserId = @appUserId
      `),
    pool
      .request()
      .input("appUserId", sql.UniqueIdentifier, appUserId)
      .query(`
        SELECT TOP (100)
          pi.Id,
          pi.ProjectId,
          p.Name AS ProjectName,
          pi.Amount,
          pi.Remark,
          pi.Status,
          pi.InvestPackageId,
          ip.Name AS PackageName,
          ip.Price AS PackagePrice,
          pi.TransactionHash,
          pi.CreatedOn
        FROM dbo.ProjectInvests pi
        LEFT JOIN dbo.Projects p ON p.Id = pi.ProjectId
        LEFT JOIN dbo.InvestPackages ip ON ip.Id = pi.InvestPackageId
        WHERE pi.AppUserId = @appUserId
        ORDER BY pi.CreatedOn DESC, pi.Id DESC
      `)
  ]);

  const summaryRow = summaryResult.recordset[0] || {};

  return {
    projects: projectsResult.recordset.map(formatProjectRow),
    packages: packagesResult.recordset.map(formatInvestPackageRow),
    summary: {
      investCount: Number(summaryRow.InvestCount || 0),
      totalInvested: toNumber(summaryRow.TotalInvested)
    },
    investments: investmentsResult.recordset.map(formatProjectInvestRow)
  };
}

async function getInvestActivationContext(transaction, projectId, packageId, userId) {
  const request = new sql.Request(transaction);
  request.input("projectId", sql.Int, projectId || null);
  request.input("packageId", sql.Int, packageId);
  request.input("userId", sql.UniqueIdentifier, userId);

  const query = `
    SELECT TOP 1
      u.Id,
      u.UserName,
      u.Email,
      u.ConsumptionBalance,
      u.AffiliateBalance,
      u.AccumulateBalance,
      u.SavingBalance,
      u.BusinessBalance,
      u.InvestBalance
    FROM dbo.Users u WITH (UPDLOCK, ROWLOCK)
    WHERE u.Id = @userId;

    SELECT TOP 1
      p.Id,
      p.Name,
      p.Status,
      p.InvestBalance
    FROM dbo.Projects p WITH (UPDLOCK, ROWLOCK)
    WHERE (@projectId IS NULL AND ISNULL(p.Status, 0) = 1)
       OR (p.Id = @projectId AND ISNULL(p.Status, 0) = 1)
    ORDER BY p.Id ASC;

    SELECT TOP 1
      ip.Id,
      ip.Name,
      ip.Price,
      ip.Image,
      ip.OrderIndex,
      ip.Status
    FROM dbo.InvestPackages ip
    WHERE ip.Id = @packageId
      AND ISNULL(ip.Status, 0) = 1;
  `;

  const result = await request.query(query);
  return {
    user: result.recordsets[0][0] || null,
    project: result.recordsets[1][0] || null,
    investPackage: result.recordsets[2][0] || null
  };
}

function authMiddleware(req, res, next) {
  const raw = req.headers.authorization || "";
  const token = raw.startsWith("Bearer ") ? raw.slice(7) : "";
  if (!token) {
    return res.status(401).json({ message: "Missing bearer token" });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.auth = payload;
    return next();
  } catch (_err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", ALLOW_ORIGIN);
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

app.get("/local-api/health", async (_req, res) => {
  try {
    const pool = await getPool();
    await pool.request().query("SELECT 1 AS ok");
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.post("/local-identity/connect/token", async (req, res) => {
  try {
    const login = req.body.UserName || req.body.username || req.body.userName || req.body.email;
    const password = req.body.Password || req.body.password;
    if (!login || !password) {
      return res.status(400).json({ error: "invalid_request", error_description: "Missing credentials" });
    }

    const user = await getUserByLogin(login);
    if (!user) {
      return res.status(401).json({ error: "invalid_grant", error_description: "Sai tài khoản hoặc mật khẩu" });
    }

    const isValid = verifyAspNetIdentityHash(user.PasswordHash, password);
    if (!isValid) {
      return res.status(401).json({ error: "invalid_grant", error_description: "Sai tài khoản hoặc mật khẩu" });
    }

    if (EMAIL_VERIFICATION_REQUIRED && !user.EmailConfirmed) {
      return res.status(403).json({ error: "email_not_confirmed", error_description: "Tài khoản chưa xác thực email" });
    }

    const payload = {
      sub: String(user.Id),
      email: user.Email || "",
      userName: user.UserName || user.Email || ""
    };
    const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRES_SEC });
    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: TOKEN_EXPIRES_SEC
    });
  } catch (err) {
    return res.status(500).json({ error: "server_error", error_description: err.message });
  }
});

app.get("/local-api/users/GetUserInfo", authMiddleware, async (req, res) => {
  try {
    const user = await getUserWithRoles(req.auth.sub);
    if (!user) {
      return res.status(404).json({ message: "Không tìm thấy tài khoản" });
    }
    return res.json({ isSuccess: true, result: user });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.get("/local-api/admin/overview", authMiddleware, requireRoles(["Admin", "Support"]), async (req, res) => {
  try {
    const pool = await getPool();

    const userId = req.auth.sub;
    const currentUser = await getUserWithRoles(userId);

    const usersResult = await pool.request().query(`
      SELECT
        u.Id,
        u.Email,
        u.UserName,
        u.EmailConfirmed,
        STRING_AGG(r.Name, ',') WITHIN GROUP (ORDER BY r.Name) AS Roles
      FROM dbo.Users u
      LEFT JOIN dbo.UserRoles ur ON ur.UserId = u.Id
      LEFT JOIN dbo.Roles r ON r.Id = ur.RoleId
      GROUP BY u.Id, u.Email, u.UserName, u.EmailConfirmed
      ORDER BY u.Email
    `);

    const rolesResult = await pool.request().query(`
      SELECT p.RoleId, r.Name AS RoleName, p.FunctionId, f.Name AS FunctionName, f.ParentId, parent.Name AS ParentName, p.Feature
      FROM dbo.Permissions p
      JOIN dbo.Roles r ON p.RoleId = r.Id
      JOIN dbo.Functions f ON p.FunctionId = f.Id
      LEFT JOIN dbo.Functions parent ON parent.Id = f.ParentId
      ORDER BY r.Name, f.Name
    `);

    const functionsResult = await pool.request().query(`
      SELECT Id, Name, Url, ParentId
      FROM dbo.Functions
      ORDER BY ParentId, Name
    `);

    const storesResult = await pool.request().query(`
      SELECT TOP 50 Id, Name, Email, PhoneNumber AS Phone, Address, Status, CreatedOn
      FROM dbo.Stores
      ORDER BY CreatedOn DESC
    `);

    const projectsResult = await pool.request().query(`
      SELECT TOP 50 Id, Name, InvestBalance, Status, CreatedOn
      FROM dbo.Projects
      ORDER BY CreatedOn DESC
    `);

    const packagesResult = await pool.request().query(`
      SELECT TOP 50 Id, Name, Price, OrderIndex, Status
      FROM dbo.InvestPackages
      ORDER BY OrderIndex
    `);

    const rolesListResult = await pool.request().query(`
      SELECT Id, Name, NormalizedName FROM dbo.Roles ORDER BY Name
    `);

    const roleClaimsResult = await pool.request().query(`
      SELECT rc.RoleId, r.Name AS RoleName, rc.ClaimType, rc.ClaimValue
      FROM dbo.RoleClaims rc
      JOIN dbo.Roles r ON rc.RoleId = r.Id
      ORDER BY r.Name
    `);

    const userRolesResult = await pool.request().query(`
      SELECT ur.UserId, ur.RoleId, u.Email, u.UserName, r.Name AS RoleName
      FROM dbo.UserRoles ur
      JOIN dbo.Users u ON u.Id = ur.UserId
      JOIN dbo.Roles r ON r.Id = ur.RoleId
      ORDER BY u.Email, r.Name
    `);

    const investHistoryResult = await pool.request().query(`
      SELECT TOP 200
        pi.Id,
        pi.ProjectId,
        p.Name AS ProjectName,
        pi.AppUserId,
        u.Email AS UserEmail,
        u.UserName AS UserName,
        pi.Amount,
        pi.Status,
        pi.CreatedOn,
        pi.InvestPackageId,
        ip.Name AS PackageName,
        pi.TransactionHash
      FROM dbo.ProjectInvests pi
      LEFT JOIN dbo.Users u ON u.Id = pi.AppUserId
      LEFT JOIN dbo.Projects p ON p.Id = pi.ProjectId
      LEFT JOIN dbo.InvestPackages ip ON ip.Id = pi.InvestPackageId
      ORDER BY pi.CreatedOn DESC
    `);

    const walletTx = {};
    async function fetchWalletTx(tableName, label) {
      const q = `
        SELECT TOP 200
          '${label}' AS WalletType,
          Id,
          TransactionHash,
          AddressFrom,
          AddressTo,
          Fee,
          FeeAmount,
          AmountReceive,
          Amount,
          AppUserId,
          Type,
          Remark,
          DateCreated
        FROM dbo.${tableName}
        ORDER BY DateCreated DESC`;
      const r = await pool.request().query(q);
      return r.recordset || [];
    }

    walletTx.consumption = await fetchWalletTx("WalletConsumptionTransactions", "consumption");
    walletTx.affiliate = await fetchWalletTx("WalletAffiliateTransactions", "affiliate");
    walletTx.accumulate = await fetchWalletTx("WalletAccumulateTransactions", "accumulate");
    walletTx.saving = await fetchWalletTx("WalletSavingTransactions", "saving");
    walletTx.business = await fetchWalletTx("WalletBusinessTransactions", "business");

    const countsResult = await pool.request().query(`
      SELECT
        (SELECT COUNT(*) FROM dbo.Users)                         AS users,
        (SELECT COUNT(*) FROM dbo.Roles)                         AS roles,
        (SELECT COUNT(*) FROM dbo.Functions)                     AS functions,
        (SELECT COUNT(*) FROM dbo.Stores)                        AS stores,
        (SELECT COUNT(*) FROM dbo.Projects)                      AS projects,
        (SELECT SUM(ISNULL(InvestBalance,0)) FROM dbo.Projects)  AS projectsInvestBalance,
        (SELECT COUNT(*) FROM dbo.InvestPackages)                AS packages,
        (SELECT COUNT(*) FROM dbo.ProjectInvests)                AS investHistory,
        (SELECT SUM(ISNULL(Amount,0)) FROM dbo.ProjectInvests)   AS investHistoryAmount,
        (SELECT COUNT(*) FROM dbo.WalletConsumptionTransactions) AS consumption,
        (SELECT COUNT(*) FROM dbo.WalletAffiliateTransactions)   AS affiliate,
        (SELECT COUNT(*) FROM dbo.WalletAccumulateTransactions)  AS accumulate,
        (SELECT COUNT(*) FROM dbo.WalletSavingTransactions)      AS saving,
        (SELECT COUNT(*) FROM dbo.WalletBusinessTransactions)    AS business,
        (SELECT COUNT(*) FROM dbo.Permissions)                   AS permissions,
        (SELECT COUNT(*) FROM dbo.RoleClaims)                    AS roleClaims,
        (SELECT COUNT(*) FROM dbo.UserRoles)                     AS userRoles
    `);

    return res.json({
      isSuccess: true,
      result: {
        currentUser,
        users: usersResult.recordset || [],
        permissions: rolesResult.recordset || [],
        functions: functionsResult.recordset || [],
        stores: storesResult.recordset || [],
        projects: projectsResult.recordset || [],
        packages: packagesResult.recordset || [],
        roles: rolesListResult.recordset || [],
        roleClaims: roleClaimsResult.recordset || [],
        userRoles: userRolesResult.recordset || [],
        investHistory: investHistoryResult.recordset || [],
        walletTx,
  counts: countsResult.recordset?.[0] || {}
      }
    });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.post("/local-api/admin/reset-password", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const email = String(req.body.email || "").trim();
    const newPassword = String(req.body.newPassword || "").trim();
    if (!email || !newPassword) {
      return res.status(400).json({ message: "Thiếu email hoặc mật khẩu mới" });
    }
    const user = await getUserByLogin(email);
    if (!user) {
      return res.status(404).json({ message: "Không tìm thấy tài khoản" });
    }
    const passwordHash = hashAspNetIdentityV3(newPassword);

    const pool = await getPool();
    await pool
      .request()
      .input("id", sql.UniqueIdentifier, user.Id)
      .input("passwordHash", sql.NVarChar(sql.MAX), passwordHash)
      .query(`
        UPDATE dbo.Users
        SET PasswordHash = @passwordHash,
            SecurityStamp = NEWID(),
            ConcurrencyStamp = NEWID(),
            ModifiedOn = GETDATE()
        WHERE Id = @id
      `);

    return res.json({ isSuccess: true, message: "Đặt lại mật khẩu thành công" });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

// --------- Quản trị Stores (Đối tác)
function normalizeInt(value, fallback = null) {
  const n = Number(value);
  if (Number.isInteger(n)) return n;
  return fallback;
}

const tableColumnsCache = {};
async function getTableColumns(table) {
  const key = String(table || "").toLowerCase();
  if (tableColumnsCache[key]) return tableColumnsCache[key];
  const pool = await getPool();
  const result = await pool
    .request()
    .input("table", sql.NVarChar(256), table)
    .query(`
      SELECT COLUMN_NAME
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = @table
      ORDER BY ORDINAL_POSITION
    `);
  const cols = (result.recordset || []).map((r) => r.COLUMN_NAME);
  tableColumnsCache[key] = cols;
  return cols;
}

function isValidTableName(name) {
  return /^[A-Za-z0-9_\\.]+$/.test(name || "");
}

function buildPaged(query, page = 1, pageSize = 20) {
  const safePageSize = [20, 50, 100].includes(Number(pageSize)) ? Number(pageSize) : 20;
  const safePage = Math.max(Number(page) || 1, 1);
  const offset = (safePage - 1) * safePageSize;
  return `${query} OFFSET ${offset} ROWS FETCH NEXT ${safePageSize} ROWS ONLY`;
}

app.get("/local-api/admin/stores", authMiddleware, requireRoles(["Admin", "Support"]), async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    const top = Math.min(Math.max(Number(req.query.top) || 100, 1), 500);
    const pool = await getPool();
    const columns = await getTableColumns("Stores");
    const selectList = columns.length ? columns.map((c) => `[${c}]`).join(", ") : `
      Id, Name, Description, Email, PhoneNumber, Address, Status, CategoryId, AppUserId, CreatedOn, ModifiedOn
    `;
    const request = pool.request().input("top", sql.Int, top);
    let where = "";
    if (q) {
      request.input("q", sql.NVarChar(512), `%${q.toUpperCase()}%`);
      where = `
        WHERE UPPER(ISNULL(Name,'')) LIKE @q
           OR UPPER(ISNULL(Email,'')) LIKE @q
           OR UPPER(ISNULL(PhoneNumber,'')) LIKE @q
           OR UPPER(ISNULL(Address,'')) LIKE @q
      `;
    }
    const result = await request.query(`
      SELECT TOP (@top)
        ${selectList}
      FROM dbo.Stores
      ${where}
      ORDER BY CreatedOn DESC
    `);
    return res.json({ isSuccess: true, result: result.recordset || [] });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

async function resolveUserIdByEmail(pool, email, currentUserId) {
  const trimmed = String(email || "").trim();
  if (!trimmed) return currentUserId;
  const user = await pool
    .request()
    .input("lookup", sql.NVarChar(256), trimmed.toUpperCase())
    .query(`
      SELECT TOP 1 Id FROM dbo.Users
      WHERE UPPER(ISNULL(Email,'')) = @lookup OR UPPER(ISNULL(UserName,'')) = @lookup
    `);
  return user.recordset[0]?.Id || currentUserId;
}

app.post("/local-api/admin/stores", authMiddleware, requireRoles(["Admin", "Support"]), async (req, res) => {
  try {
    const pool = await getPool();
    const columns = await getTableColumns("Stores");
    const body = req.body || {};
    const name = String(body.name || "").trim();
    const description = String(body.description || "").trim();
    const address = String(body.address || "").trim();
    const email = String(body.email || "").trim();
    const phone = String(body.phone || "").trim();
    const categoryId = normalizeInt(body.categoryId, 1) || 1;
    const status = normalizeInt(body.status, 1) ?? 1;
    const ownerEmail = String(body.ownerEmail || email || "").trim();
    if (!name || !description || !address) {
      return res.status(400).json({ isSuccess: false, message: "Thiếu tên, mô tả hoặc địa chỉ" });
    }
    const appUserId = await resolveUserIdByEmail(pool, ownerEmail, req.auth.sub);
    const reqDb = pool.request();
    const fields = [];
    const values = [];
    const addField = (col, val, type) => {
      if (!columns.includes(col)) return;
      const param = `@${col}`;
      fields.push(`[${col}]`);
      values.push(param);
      reqDb.input(col, type, val);
    };
    addField("Name", name, sql.NVarChar(sql.MAX));
    addField("Description", description, sql.NVarChar(sql.MAX));
    addField("Email", email || null, sql.NVarChar(512));
    addField("PhoneNumber", phone || null, sql.NVarChar(512));
    addField("Address", address, sql.NVarChar(sql.MAX));
    addField("Status", status, sql.Int);
    addField("CategoryId", categoryId, sql.Int);
    addField("AppUserId", appUserId, sql.UniqueIdentifier);
    addField("MapEmbed", body.mapEmbed || null, sql.NVarChar(sql.MAX));
    addField("MapEmbedHtml", body.mapEmbed || null, sql.NVarChar(sql.MAX));
    addField("MapIframe", body.mapEmbed || null, sql.NVarChar(sql.MAX));
    addField("Latitude", body.latitude ?? null, sql.Decimal(18, 8));
    addField("Longitude", body.longitude ?? null, sql.Decimal(18, 8));
    addField("Url", body.url || null, sql.NVarChar(sql.MAX));
    addField("Logo", body.logo || null, sql.NVarChar(sql.MAX));
    addField("Thumbnail", body.thumbnail || null, sql.NVarChar(sql.MAX));
    if (columns.includes("CreatedOn")) { fields.push("[CreatedOn]"); values.push("GETDATE()"); }
    if (columns.includes("ModifiedOn")) { fields.push("[ModifiedOn]"); values.push("GETDATE()"); }
    if (!fields.length) return res.status(400).json({ isSuccess: false, message: "Không xác định được cột để lưu Stores" });
    const insertSql = `
      INSERT INTO dbo.Stores (${fields.join(",")})
      VALUES (${values.join(",")});
      SELECT SCOPE_IDENTITY() AS Id;
    `;
    const result = await reqDb.query(insertSql);
    return res.json({ isSuccess: true, result: { id: result.recordset[0]?.Id } });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.put("/local-api/admin/stores/:id", authMiddleware, requireRoles(["Admin", "Support"]), async (req, res) => {
  try {
    const pool = await getPool();
    const columns = await getTableColumns("Stores");
    const id = normalizeInt(req.params.id, null);
    if (id === null) return res.status(400).json({ isSuccess: false, message: "StoreId không hợp lệ" });
    const body = req.body || {};
    const name = String(body.name || "").trim();
    const description = String(body.description || "").trim();
    const address = String(body.address || "").trim();
    const email = String(body.email || "").trim();
    const phone = String(body.phone || "").trim();
    const categoryId = normalizeInt(body.categoryId, 1) || 1;
    const status = normalizeInt(body.status, 1) ?? 1;
    const ownerEmail = String(body.ownerEmail || email || "").trim();
    if (!name || !description || !address) {
      return res.status(400).json({ isSuccess: false, message: "Thiếu tên, mô tả hoặc địa chỉ" });
    }
    const appUserId = await resolveUserIdByEmail(pool, ownerEmail, req.auth.sub);
    const reqDb = pool.request().input("Id", sql.Int, id);
    const sets = [];
    const addSet = (col, val, type) => {
      if (!columns.includes(col)) return;
      const param = `@${col}`;
      sets.push(`[${col}] = ${param}`);
      reqDb.input(col, type, val);
    };
    addSet("Name", name, sql.NVarChar(sql.MAX));
    addSet("Description", description, sql.NVarChar(sql.MAX));
    addSet("Email", email || null, sql.NVarChar(512));
    addSet("PhoneNumber", phone || null, sql.NVarChar(512));
    addSet("Address", address, sql.NVarChar(sql.MAX));
    addSet("Status", status, sql.Int);
    addSet("CategoryId", categoryId, sql.Int);
    addSet("AppUserId", appUserId, sql.UniqueIdentifier);
    addSet("MapEmbed", body.mapEmbed || null, sql.NVarChar(sql.MAX));
    addSet("MapEmbedHtml", body.mapEmbed || null, sql.NVarChar(sql.MAX));
    addSet("MapIframe", body.mapEmbed || null, sql.NVarChar(sql.MAX));
    addSet("Latitude", body.latitude ?? null, sql.Decimal(18, 8));
    addSet("Longitude", body.longitude ?? null, sql.Decimal(18, 8));
    addSet("Url", body.url || null, sql.NVarChar(sql.MAX));
    addSet("Logo", body.logo || null, sql.NVarChar(sql.MAX));
    addSet("Thumbnail", body.thumbnail || null, sql.NVarChar(sql.MAX));
    if (columns.includes("ModifiedOn")) sets.push("ModifiedOn = GETDATE()");
    if (!sets.length) return res.status(400).json({ isSuccess: false, message: "Không có cột nào để cập nhật" });
    const updateSql = `
      UPDATE dbo.Stores
      SET ${sets.join(", ")}
      WHERE Id=@Id
    `;
    await reqDb.query(updateSql);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.delete("/local-api/admin/stores/:id", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const id = normalizeInt(req.params.id, null);
    if (id === null) return res.status(400).json({ isSuccess: false, message: "StoreId không hợp lệ" });
    const pool = await getPool();
    await pool.request().input("Id", sql.Int, id).query(`DELETE FROM dbo.Stores WHERE Id=@Id`);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

// --------- Quản trị phân quyền (UserRoles)
app.post("/local-api/admin/user-roles", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const email = String(req.body.email || "").trim();
    const roleId = String(req.body.roleId || "").trim();
    if (!email || !roleId) {
      return res.status(400).json({ isSuccess: false, message: "Thiếu email hoặc roleId" });
    }
    const pool = await getPool();
    const userResult = await pool
      .request()
      .input("lookup", sql.NVarChar(256), email.toUpperCase())
      .query(`
        SELECT TOP 1 Id FROM dbo.Users
        WHERE UPPER(ISNULL(Email,'')) = @lookup OR UPPER(ISNULL(UserName,'')) = @lookup
      `);
    const userId = userResult.recordset[0]?.Id;
    if (!userId) return res.status(404).json({ isSuccess: false, message: "Không tìm thấy user" });

    const roleResult = await pool
      .request()
      .input("roleId", sql.UniqueIdentifier, roleId)
      .query(`SELECT TOP 1 Id FROM dbo.Roles WHERE Id=@roleId`);
    if (!roleResult.recordset[0]) return res.status(404).json({ isSuccess: false, message: "Role không tồn tại" });

    await pool
      .request()
      .input("userId", sql.UniqueIdentifier, userId)
      .input("roleId", sql.UniqueIdentifier, roleId)
      .query(`
        IF NOT EXISTS (SELECT 1 FROM dbo.UserRoles WHERE UserId=@userId AND RoleId=@roleId)
          INSERT INTO dbo.UserRoles (UserId, RoleId) VALUES (@userId, @roleId)
      `);

    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.delete("/local-api/admin/user-roles", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const email = String(req.query.email || "").trim();
    const roleId = String(req.query.roleId || "").trim();
    if (!email || !roleId) {
      return res.status(400).json({ isSuccess: false, message: "Thiếu email hoặc roleId" });
    }
    const pool = await getPool();
    const userResult = await pool
      .request()
      .input("lookup", sql.NVarChar(256), email.toUpperCase())
      .query(`
        SELECT TOP 1 Id FROM dbo.Users
        WHERE UPPER(ISNULL(Email,'')) = @lookup OR UPPER(ISNULL(UserName,'')) = @lookup
      `);
    const userId = userResult.recordset[0]?.Id;
    if (!userId) return res.status(404).json({ isSuccess: false, message: "Không tìm thấy user" });

    await pool
      .request()
      .input("userId", sql.UniqueIdentifier, userId)
      .input("roleId", sql.UniqueIdentifier, roleId)
      .query(`DELETE FROM dbo.UserRoles WHERE UserId=@userId AND RoleId=@roleId`);

    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

// --------- Catalog explorer (Admin only)
app.get("/local-api/admin/catalog/tables", authMiddleware, requireRoles(["Admin"]), async (_req, res) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT
        s.name AS SchemaName,
        t.name AS TableName,
        CONCAT(s.name, '.', t.name) AS FullName,
        SUM(p.rows) AS RowCountValue
      FROM sys.tables t
      JOIN sys.schemas s ON t.schema_id = s.schema_id
      JOIN sys.partitions p ON t.object_id = p.object_id
      WHERE p.index_id IN (0,1)
      GROUP BY s.name, t.name
      ORDER BY RowCountValue DESC, FullName
    `);
    return res.json({ isSuccess: true, result: result.recordset || [] });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

// lấy toàn bộ bảng + dữ liệu top N cho admin xem nhanh
app.get("/local-api/admin/catalog/all", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const top = Math.min(Math.max(Number(req.query.top) || 50, 1), 200);
    const pool = await getPool();
    const tablesResult = await pool.request().query(`
      SELECT s.name AS SchemaName, t.name AS TableName, CONCAT(s.name, '.', t.name) AS FullName
      FROM sys.tables t
      JOIN sys.schemas s ON t.schema_id = s.schema_id
      ORDER BY s.name, t.name
    `);
    const list = tablesResult.recordset || [];
    const result = [];
    for (const t of list) {
      const schema = t.SchemaName || "dbo";
      const table = t.TableName;
      if (!isValidTableName(table)) continue;
      const columnsResult = await pool.request()
        .input("schema", sql.NVarChar(128), schema)
        .input("table", sql.NVarChar(128), table)
        .query(`
          SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH
          FROM INFORMATION_SCHEMA.COLUMNS
          WHERE TABLE_SCHEMA=@schema AND TABLE_NAME=@table
          ORDER BY ORDINAL_POSITION
        `);
      const dataResult = await pool.request().query(`
        DECLARE @sql NVARCHAR(MAX) = N'SELECT TOP (${top}) * FROM ' + QUOTENAME('${schema}') + '.' + QUOTENAME('${table}');
        EXEC(@sql);
      `);
      result.push({
        schema,
        table,
        fullName: `${schema}.${table}`,
        columns: columnsResult.recordset || [],
        rows: dataResult.recordset || []
      });
    }
    return res.json({ isSuccess: true, result });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.get("/local-api/admin/catalog/table", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const name = String(req.query.name || "").trim();
    const top = Math.min(Math.max(Number(req.query.top) || 200, 1), 1000);
    if (!name || !isValidTableName(name)) {
      return res.status(400).json({ isSuccess: false, message: "Tên bảng không hợp lệ" });
    }
    const [schemaName, tableName] = name.includes(".") ? name.split(".") : ["dbo", name];
    if (!schemaName || !tableName) {
      return res.status(400).json({ isSuccess: false, message: "Tên bảng không hợp lệ" });
    }
    const pool = await getPool();
    const request = pool.request()
      .input("top", sql.Int, top)
      .input("schema", sql.NVarChar(128), schemaName)
      .input("table", sql.NVarChar(128), tableName);

    const sqlText = `
      DECLARE @sql NVARCHAR(MAX) = N'SELECT TOP (' + CAST(@top AS NVARCHAR(10)) + N') * FROM '
        + QUOTENAME(@schema) + N'.' + QUOTENAME(@table);
      EXEC sp_executesql @sql;
    `;
    const dataResult = await request.query(sqlText);

    const columnsResult = await pool.request()
      .input("schema", sql.NVarChar(128), schemaName)
      .input("table", sql.NVarChar(128), tableName)
      .query(`
        SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = @schema AND TABLE_NAME = @table
        ORDER BY ORDINAL_POSITION
      `);

    return res.json({
      isSuccess: true,
      result: {
        table: `${schemaName}.${tableName}`,
        top,
        columns: columnsResult.recordset || [],
        rows: dataResult.recordset || []
      }
    });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

// --------- Paged wallet transactions
const walletTableMap = {
  consumption: "WalletConsumptionTransactions",
  affiliate: "WalletAffiliateTransactions",
  accumulate: "WalletAccumulateTransactions",
  saving: "WalletSavingTransactions",
  business: "WalletBusinessTransactions"
};

app.get("/local-api/admin/wallet-tx", authMiddleware, requireRoles(["Admin", "Support"]), async (req, res) => {
  try {
    const type = String(req.query.wallet || "consumption").toLowerCase();
    const table = walletTableMap[type] || walletTableMap.consumption;
    const page = Math.max(Number(req.query.page) || 1, 1);
    const pageSize = [20, 50, 100].includes(Number(req.query.pageSize)) ? Number(req.query.pageSize) : 20;
    const offset = (page - 1) * pageSize;
    const pool = await getPool();
    const totalResult = await pool.request().query(`SELECT COUNT(*) AS Total FROM dbo.${table}`);
    const total = totalResult.recordset[0]?.Total || 0;
    const dataResult = await pool.request().query(`
      SELECT Id, TransactionHash, AddressFrom, AddressTo, Fee, FeeAmount, AmountReceive, Amount,
             AppUserId, Type, Remark, DateCreated
      FROM dbo.${table}
      ORDER BY DateCreated DESC
      OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY
    `);
    return res.json({ isSuccess: true, result: { items: dataResult.recordset || [], total, page, pageSize, wallet: type } });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

// --------- Paged invest history
app.get("/local-api/admin/invest-history", authMiddleware, requireRoles(["Admin", "Support"]), async (req, res) => {
  try {
    const page = Math.max(Number(req.query.page) || 1, 1);
    const pageSize = [20, 50, 100].includes(Number(req.query.pageSize)) ? Number(req.query.pageSize) : 20;
    const offset = (page - 1) * pageSize;
    const pool = await getPool();
    const totalResult = await pool.request().query(`SELECT COUNT(*) AS Total FROM dbo.ProjectInvests`);
    const total = totalResult.recordset[0]?.Total || 0;
    const dataResult = await pool.request().query(`
      SELECT
        pi.Id,
        pi.ProjectId,
        p.Name AS ProjectName,
        pi.AppUserId,
        u.Email AS UserEmail,
        u.UserName AS UserName,
        pi.Amount,
        pi.Status,
        pi.CreatedOn,
        pi.InvestPackageId,
        ip.Name AS PackageName,
        pi.TransactionHash
      FROM dbo.ProjectInvests pi
      LEFT JOIN dbo.Users u ON u.Id = pi.AppUserId
      LEFT JOIN dbo.Projects p ON p.Id = pi.ProjectId
      LEFT JOIN dbo.InvestPackages ip ON ip.Id = pi.InvestPackageId
      ORDER BY pi.CreatedOn DESC
      OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY
    `);
    return res.json({ isSuccess: true, result: { items: dataResult.recordset || [], total, page, pageSize } });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

// --------- Users CRUD (Admin)
app.get("/local-api/admin/users", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    const page = Math.max(Number(req.query.page) || 1, 1);
    const pageSize = [20, 50, 100].includes(Number(req.query.pageSize)) ? Number(req.query.pageSize) : 20;
    const offset = (page - 1) * pageSize;
    const pool = await getPool();
    let where = "";
    const request = pool.request();
    if (q) {
      request.input("q", sql.NVarChar(256), `%${q.toUpperCase()}%`);
      where = `
        WHERE UPPER(ISNULL(Email,'')) LIKE @q
           OR UPPER(ISNULL(UserName,'')) LIKE @q
           OR UPPER(ISNULL(Fullname,'')) LIKE @q
      `;
    }
    const totalResult = await request.query(`
      SELECT COUNT(*) AS Total FROM dbo.Users ${where}
    `);
    const total = totalResult.recordset[0]?.Total || 0;
    const dataResult = await request.query(`
      SELECT Id, Email, UserName, Fullname, PhoneNumber, EmailConfirmed, Status, CreatedOn, ModifiedOn
      FROM dbo.Users
      ${where}
      ORDER BY CreatedOn DESC
      OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY
    `);
    return res.json({ isSuccess: true, result: { items: dataResult.recordset || [], total, page, pageSize } });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.post("/local-api/admin/users", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const { email, fullName, phone, password, status = 1, emailConfirmed = true } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ isSuccess: false, message: "Thiếu email hoặc mật khẩu" });
    }
    const pwdHash = hashAspNetIdentityV3(password);
    const pool = await getPool();
    const r = await pool
      .request()
      .input("Email", sql.NVarChar(256), email)
      .input("UserName", sql.NVarChar(256), email)
      .input("NormalizedEmail", sql.NVarChar(256), email.toUpperCase())
      .input("NormalizedUserName", sql.NVarChar(256), email.toUpperCase())
      .input("Fullname", sql.NVarChar(256), fullName || "")
      .input("PhoneNumber", sql.NVarChar(50), phone || null)
      .input("PasswordHash", sql.NVarChar(sql.MAX), pwdHash)
      .input("Status", sql.Int, status)
      .input("EmailConfirmed", sql.Bit, emailConfirmed ? 1 : 0)
      .query(`
        INSERT INTO dbo.Users (Id, Email, UserName, NormalizedEmail, NormalizedUserName, Fullname, PhoneNumber, PasswordHash, Status, EmailConfirmed, CreatedOn, ModifiedOn)
        VALUES (NEWID(), @Email, @UserName, @NormalizedEmail, @NormalizedUserName, @Fullname, @PhoneNumber, @PasswordHash, @Status, @EmailConfirmed, GETDATE(), GETDATE());
        SELECT TOP 1 Id FROM dbo.Users WHERE Email=@Email;
      `);
    return res.json({ isSuccess: true, result: { id: r.recordset[0]?.Id } });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.put("/local-api/admin/users/:id", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const id = req.params.id;
    const { email, fullName, phone, password, status, emailConfirmed } = req.body || {};
    const pool = await getPool();
    const pwdClause = password ? ", PasswordHash=@PasswordHash" : "";
    const request = pool
      .request()
      .input("Id", sql.UniqueIdentifier, id)
      .input("Email", sql.NVarChar(256), email || null)
      .input("UserName", sql.NVarChar(256), email || null)
      .input("NormalizedEmail", sql.NVarChar(256), email ? email.toUpperCase() : null)
      .input("NormalizedUserName", sql.NVarChar(256), email ? email.toUpperCase() : null)
      .input("Fullname", sql.NVarChar(256), fullName || null)
      .input("PhoneNumber", sql.NVarChar(50), phone || null)
      .input("Status", sql.Int, status ?? 1)
      .input("EmailConfirmed", sql.Bit, emailConfirmed ? 1 : 0);
    if (password) request.input("PasswordHash", sql.NVarChar(sql.MAX), hashAspNetIdentityV3(password));
    await request.query(`
      UPDATE dbo.Users
      SET Email=@Email, UserName=@UserName, NormalizedEmail=@NormalizedEmail, NormalizedUserName=@NormalizedUserName,
          Fullname=@Fullname, PhoneNumber=@PhoneNumber, Status=@Status, EmailConfirmed=@EmailConfirmed,
          ModifiedOn=GETDATE()
          ${pwdClause}
      WHERE Id=@Id
    `);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.delete("/local-api/admin/users/:id", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const id = req.params.id;
    const pool = await getPool();
    await pool.request().input("Id", sql.UniqueIdentifier, id).query(`DELETE FROM dbo.Users WHERE Id=@Id`);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

// --------- Roles CRUD (Admin)
app.post("/local-api/admin/roles", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const { name } = req.body || {};
    if (!name) return res.status(400).json({ isSuccess: false, message: "Thiếu tên role" });
    const pool = await getPool();
    const r = await pool.request()
      .input("Name", sql.NVarChar(256), name)
      .input("NormalizedName", sql.NVarChar(256), name.toUpperCase())
      .query(`
        INSERT INTO dbo.Roles (Id, Name, NormalizedName) VALUES (NEWID(), @Name, @NormalizedName);
        SELECT SCOPE_IDENTITY();
      `);
    return res.json({ isSuccess: true, result: r.recordset?.[0] || {} });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.put("/local-api/admin/roles/:id", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const id = req.params.id;
    const { name } = req.body || {};
    if (!name) return res.status(400).json({ isSuccess: false, message: "Thiếu tên role" });
    const pool = await getPool();
    await pool.request()
      .input("Id", sql.UniqueIdentifier, id)
      .input("Name", sql.NVarChar(256), name)
      .input("NormalizedName", sql.NVarChar(256), name.toUpperCase())
      .query(`UPDATE dbo.Roles SET Name=@Name, NormalizedName=@NormalizedName WHERE Id=@Id`);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.delete("/local-api/admin/roles/:id", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const id = req.params.id;
    const protectedIds = ["8497F93F-D389-494E-8A42-F58F3715B809"]; // Admin role
    if (protectedIds.includes(String(id).toUpperCase())) {
      return res.status(400).json({ isSuccess: false, message: "Không thể xóa role hệ thống" });
    }
    const pool = await getPool();
    await pool.request().input("Id", sql.UniqueIdentifier, id).query(`DELETE FROM dbo.Roles WHERE Id=@Id`);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

// --------- Permissions CRUD (Admin)
app.get("/local-api/admin/permissions", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const roleId = req.query.roleId ? String(req.query.roleId) : null;
    const pool = await getPool();
    const q = `
      SELECT p.RoleId, r.Name AS RoleName, p.FunctionId, f.Name AS FunctionName, f.ParentId, f.Url, p.Feature
      FROM dbo.Permissions p
      JOIN dbo.Roles r ON r.Id = p.RoleId
      JOIN dbo.Functions f ON f.Id = p.FunctionId
      ${roleId ? "WHERE p.RoleId = @RoleId" : ""}
      ORDER BY r.Name, f.Name
    `;
    const result = await pool.request().input("RoleId", sql.UniqueIdentifier, roleId || null).query(q);
    return res.json({ isSuccess: true, result: result.recordset || [] });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.post("/local-api/admin/permissions", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const { roleId, functionId, feature } = req.body || {};
    if (!roleId || !functionId) return res.status(400).json({ isSuccess: false, message: "Thiếu roleId hoặc functionId" });
    const pool = await getPool();
    await pool.request()
      .input("RoleId", sql.UniqueIdentifier, roleId)
      .input("FunctionId", sql.NVarChar(128), functionId)
      .input("Feature", sql.NVarChar(1000), feature || "index")
      .query(`
        IF NOT EXISTS (SELECT 1 FROM dbo.Permissions WHERE RoleId=@RoleId AND FunctionId=@FunctionId)
          INSERT INTO dbo.Permissions (RoleId, FunctionId, Feature) VALUES (@RoleId, @FunctionId, @Feature)
        ELSE
          UPDATE dbo.Permissions SET Feature=@Feature WHERE RoleId=@RoleId AND FunctionId=@FunctionId
      `);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.delete("/local-api/admin/permissions", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const roleId = String(req.query.roleId || "");
    const functionId = String(req.query.functionId || "");
    if (!roleId || !functionId) return res.status(400).json({ isSuccess: false, message: "Thiếu roleId hoặc functionId" });
    const pool = await getPool();
    await pool.request()
      .input("RoleId", sql.UniqueIdentifier, roleId)
      .input("FunctionId", sql.NVarChar(128), functionId)
      .query(`DELETE FROM dbo.Permissions WHERE RoleId=@RoleId AND FunctionId=@FunctionId`);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

// --------- Functions CRUD (Admin)
app.get("/local-api/admin/functions", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const page = Math.max(Number(req.query.page) || 1, 1);
    const pageSize = [20, 50, 100].includes(Number(req.query.pageSize)) ? Number(req.query.pageSize) : 20;
    const offset = (page - 1) * pageSize;
    const pool = await getPool();
    const totalResult = await pool.request().query(`SELECT COUNT(*) AS Total FROM dbo.Functions`);
    const total = totalResult.recordset[0]?.Total || 0;
    const dataResult = await pool.request().query(`
      SELECT Id, Name, Url, ParentId, SortOrder, Status
      FROM dbo.Functions
      ORDER BY SortOrder, Name
      OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY
    `);
    return res.json({ isSuccess: true, result: { items: dataResult.recordset || [], total, page, pageSize } });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.post("/local-api/admin/functions", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const { id, name, url, parentId = null, sortOrder = 0, status = 1 } = req.body || {};
    if (!id || !name) return res.status(400).json({ isSuccess: false, message: "Thiếu Id hoặc Name" });
    const pool = await getPool();
    await pool.request()
      .input("Id", sql.NVarChar(128), id)
      .input("Name", sql.NVarChar(256), name)
      .input("Url", sql.NVarChar(sql.MAX), url || "")
      .input("ParentId", sql.NVarChar(128), parentId || null)
      .input("SortOrder", sql.Int, sortOrder || 0)
      .input("Status", sql.Int, status || 1)
      .query(`
        INSERT INTO dbo.Functions (Id, Name, Url, ParentId, SortOrder, Status)
        VALUES (@Id, @Name, @Url, @ParentId, @SortOrder, @Status)
      `);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.put("/local-api/admin/functions/:id", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const id = req.params.id;
    const { name, url, parentId = null, sortOrder = 0, status = 1 } = req.body || {};
    const pool = await getPool();
    await pool.request()
      .input("Id", sql.NVarChar(128), id)
      .input("Name", sql.NVarChar(256), name || "")
      .input("Url", sql.NVarChar(sql.MAX), url || "")
      .input("ParentId", sql.NVarChar(128), parentId || null)
      .input("SortOrder", sql.Int, sortOrder || 0)
      .input("Status", sql.Int, status || 1)
      .query(`
        UPDATE dbo.Functions
        SET Name=@Name, Url=@Url, ParentId=@ParentId, SortOrder=@SortOrder, Status=@Status
        WHERE Id=@Id
      `);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.delete("/local-api/admin/functions/:id", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const id = req.params.id;
    const protectedIds = ["SYSTEM_MANAGEMENT", "ADMIN"]; // tránh xóa gốc
    if (protectedIds.includes(String(id).toUpperCase())) {
      return res.status(400).json({ isSuccess: false, message: "Không thể xóa function hệ thống" });
    }
    const pool = await getPool();
    await pool.request().input("Id", sql.NVarChar(128), id).query(`DELETE FROM dbo.Functions WHERE Id=@Id`);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

// --------- Projects CRUD (Admin)
app.get("/local-api/admin/projects", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const page = Math.max(Number(req.query.page) || 1, 1);
    const pageSize = [20, 50, 100].includes(Number(req.query.pageSize)) ? Number(req.query.pageSize) : 20;
    const offset = (page - 1) * pageSize;
    const pool = await getPool();
    const totalResult = await pool.request().query(`SELECT COUNT(*) AS Total FROM dbo.Projects`);
    const total = totalResult.recordset[0]?.Total || 0;
    const dataResult = await pool.request().query(`
      SELECT Id, Name, Description, InvestBalance, Status, CreatedOn, ModifiedOn
      FROM dbo.Projects
      ORDER BY CreatedOn DESC
      OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY
    `);
    return res.json({ isSuccess: true, result: { items: dataResult.recordset || [], total, page, pageSize } });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.post("/local-api/admin/projects", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const { name, description, investBalance = 0, status = 1 } = req.body || {};
    if (!name) return res.status(400).json({ isSuccess: false, message: "Thiếu tên dự án" });
    const pool = await getPool();
    await pool.request()
      .input("Name", sql.NVarChar(256), name)
      .input("Description", sql.NVarChar(sql.MAX), description || "")
      .input("InvestBalance", sql.Decimal(18, 2), investBalance || 0)
      .input("Status", sql.Int, status || 1)
      .query(`
        INSERT INTO dbo.Projects (Name, Description, InvestBalance, Status, CreatedOn, ModifiedOn)
        VALUES (@Name, @Description, @InvestBalance, @Status, GETDATE(), GETDATE())
      `);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.put("/local-api/admin/projects/:id", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const id = req.params.id;
    const { name, description, investBalance = 0, status = 1 } = req.body || {};
    const pool = await getPool();
    await pool.request()
      .input("Id", sql.Int, id)
      .input("Name", sql.NVarChar(256), name || "")
      .input("Description", sql.NVarChar(sql.MAX), description || "")
      .input("InvestBalance", sql.Decimal(18, 2), investBalance || 0)
      .input("Status", sql.Int, status || 1)
      .query(`
        UPDATE dbo.Projects
        SET Name=@Name, Description=@Description, InvestBalance=@InvestBalance, Status=@Status, ModifiedOn=GETDATE()
        WHERE Id=@Id
      `);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.delete("/local-api/admin/projects/:id", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const id = req.params.id;
    const pool = await getPool();
    await pool.request().input("Id", sql.Int, id).query(`DELETE FROM dbo.Projects WHERE Id=@Id`);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

// --------- InvestPackages CRUD (Admin)
app.get("/local-api/admin/invest-packages", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const page = Math.max(Number(req.query.page) || 1, 1);
    const pageSize = [20, 50, 100].includes(Number(req.query.pageSize)) ? Number(req.query.pageSize) : 20;
    const offset = (page - 1) * pageSize;
    const pool = await getPool();
    const totalResult = await pool.request().query(`SELECT COUNT(*) AS Total FROM dbo.InvestPackages`);
    const total = totalResult.recordset[0]?.Total || 0;
    const dataResult = await pool.request().query(`
      SELECT Id, Name, Price, OrderIndex, Status, CreatedOn
      FROM dbo.InvestPackages
      ORDER BY OrderIndex
      OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY
    `);
    return res.json({ isSuccess: true, result: { items: dataResult.recordset || [], total, page, pageSize } });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.post("/local-api/admin/invest-packages", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const { name, price = 0, orderIndex = 0, status = 1 } = req.body || {};
    if (!name) return res.status(400).json({ isSuccess: false, message: "Thiếu tên gói" });
    const pool = await getPool();
    await pool.request()
      .input("Name", sql.NVarChar(256), name)
      .input("Price", sql.Decimal(18, 2), price || 0)
      .input("OrderIndex", sql.Int, orderIndex || 0)
      .input("Status", sql.Int, status || 1)
      .query(`
        INSERT INTO dbo.InvestPackages (Name, Price, OrderIndex, Status, CreatedOn)
        VALUES (@Name, @Price, @OrderIndex, @Status, GETDATE())
      `);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.put("/local-api/admin/invest-packages/:id", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const id = req.params.id;
    const { name, price = 0, orderIndex = 0, status = 1 } = req.body || {};
    const pool = await getPool();
    await pool.request()
      .input("Id", sql.Int, id)
      .input("Name", sql.NVarChar(256), name || "")
      .input("Price", sql.Decimal(18, 2), price || 0)
      .input("OrderIndex", sql.Int, orderIndex || 0)
      .input("Status", sql.Int, status || 1)
      .query(`
        UPDATE dbo.InvestPackages
        SET Name=@Name, Price=@Price, OrderIndex=@OrderIndex, Status=@Status
        WHERE Id=@Id
      `);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.delete("/local-api/admin/invest-packages/:id", authMiddleware, requireRoles(["Admin"]), async (req, res) => {
  try {
    const id = req.params.id;
    const pool = await getPool();
    await pool.request().input("Id", sql.Int, id).query(`DELETE FROM dbo.InvestPackages WHERE Id=@Id`);
    return res.json({ isSuccess: true });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.get("/local-api/wallets/consumption/receive", authMiddleware, async (req, res) => {
  try {
    const user = await getUserById(req.auth.sub);
    if (!user) {
      return res.status(404).json({ isSuccess: false, message: "Không tìm thấy tài khoản" });
    }

    return res.json({
      isSuccess: true,
      result: {
        address: toAddress(user.Id),
        accountId: String(user.Id),
        email: user.Email || "",
        userName: user.UserName || ""
      }
    });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.get("/local-api/wallets/consumption/lookup", authMiddleware, async (req, res) => {
  try {
    const lookupAddress = toAddress(req.query.address);
    if (!lookupAddress) {
      return res.status(400).json({ isSuccess: false, message: "Thiếu địa chỉ nhận" });
    }
    if (!isGuid(lookupAddress)) {
      return res.status(400).json({ isSuccess: false, message: "Địa chỉ nhận không đúng định dạng" });
    }

    const user = await getUserById(lookupAddress);
    if (!user) {
      return res.status(404).json({ isSuccess: false, message: "Địa chỉ nhận không tồn tại" });
    }

    return res.json({
      isSuccess: true,
      result: {
        address: toAddress(user.Id),
        accountId: String(user.Id),
        email: user.Email || "",
        userName: user.UserName || ""
      }
    });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.get("/local-api/wallets/:walletType/history", authMiddleware, async (req, res) => {
  try {
    const limit = Math.min(100, Math.max(1, Number(req.query.limit || 30)));
    const items = await getWalletHistory(req.params.walletType, req.auth.sub, limit);
    if (!items) {
      return res.status(404).json({ isSuccess: false, message: "Loại ví không hợp lệ" });
    }

    return res.json({
      isSuccess: true,
      result: items
    });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.get("/local-api/projects/invest/overview", authMiddleware, async (req, res) => {
  try {
    const result = await getInvestOverview(req.auth.sub);
    return res.json({
      isSuccess: true,
      result
    });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.post("/local-api/projects/invest/activate", authMiddleware, async (req, res) => {
  const transaction = new sql.Transaction(await getPool());

  try {
    const packageId = Number(req.body.packageId);
    const projectId = req.body.projectId ? Number(req.body.projectId) : null;

    if (!Number.isInteger(packageId) || packageId <= 0) {
      return res.status(400).json({ isSuccess: false, message: "Gói đầu tư không hợp lệ" });
    }
    if (projectId !== null && (!Number.isInteger(projectId) || projectId <= 0)) {
      return res.status(400).json({ isSuccess: false, message: "Dự án không hợp lệ" });
    }

    await transaction.begin(sql.ISOLATION_LEVEL.SERIALIZABLE);

    const context = await getInvestActivationContext(transaction, projectId, packageId, req.auth.sub);
    const user = context.user;
    const project = context.project;
    const investPackage = context.investPackage;

    if (!user) {
      await transaction.rollback();
      return res.status(404).json({ isSuccess: false, message: "Không tìm thấy tài khoản" });
    }
    if (!project) {
      await transaction.rollback();
      return res.status(404).json({ isSuccess: false, message: "Không tìm thấy dự án đang hoạt động" });
    }
    if (!investPackage) {
      await transaction.rollback();
      return res.status(404).json({ isSuccess: false, message: "Không tìm thấy gói đầu tư" });
    }

    const amount = parsePositiveAmount(investPackage.Price);
    if (!amount) {
      await transaction.rollback();
      return res.status(400).json({ isSuccess: false, message: "Giá gói đầu tư không hợp lệ" });
    }

    if (toNumber(user.ConsumptionBalance) < amount) {
      await transaction.rollback();
      return res.status(400).json({ isSuccess: false, message: "Số dư ví giao dịch không đủ để kích hoạt gói" });
    }

    const savingAmount = Math.round(amount * 1.8 * 100) / 100;
    const businessAmount = Math.round(amount * 1.2 * 100) / 100;
    const investAmount = amount;
    const transactionHash = crypto.randomUUID().replace(/-/g, "");
    const userDisplay = user.Email || user.UserName || String(user.Id);
    const walletRemark = `${userDisplay} kích hoạt gói ${formatMoneyEn(amount)} VNTD đến dự án ${project.Name || ""}`.trim();
    const projectRemark = `Thanh toán gói đầu tư dự án ${project.Id} chi phí ${amount.toFixed(2)}`;

    await new sql.Request(transaction)
      .input("userId", sql.UniqueIdentifier, user.Id)
      .input("amount", sql.Decimal(18, 2), amount)
      .input("savingAmount", sql.Decimal(18, 2), savingAmount)
      .input("businessAmount", sql.Decimal(18, 2), businessAmount)
      .input("investAmount", sql.Decimal(18, 2), investAmount)
      .query(`
        UPDATE dbo.Users
        SET ConsumptionBalance = ISNULL(ConsumptionBalance, 0) - @amount,
            SavingBalance = ISNULL(SavingBalance, 0) + @savingAmount,
            BusinessBalance = ISNULL(BusinessBalance, 0) + @businessAmount,
            InvestBalance = ISNULL(InvestBalance, 0) + @investAmount,
            ModifiedOn = GETDATE()
        WHERE Id = @userId
      `);

    await new sql.Request(transaction)
      .input("projectId", sql.Int, project.Id)
      .input("amount", sql.Decimal(18, 2), amount)
      .query(`
        UPDATE dbo.Projects
        SET InvestBalance = ISNULL(InvestBalance, 0) + @amount,
            ModifiedOn = GETDATE()
        WHERE Id = @projectId
      `);

    await new sql.Request(transaction)
      .input("projectId", sql.Int, project.Id)
      .input("userId", sql.UniqueIdentifier, user.Id)
      .input("amount", sql.Decimal(18, 2), amount)
      .input("remark", sql.NVarChar(512), projectRemark)
      .input("packageId", sql.Int, investPackage.Id)
      .input("transactionHash", sql.NVarChar(128), transactionHash)
      .query(`
        INSERT INTO dbo.ProjectInvests (
          ProjectId, AppUserId, Amount, Remark, Status, CreatedOn, ModifiedOn, InvestPackageId, TransactionHash
        )
        VALUES (
          @projectId, @userId, @amount, @remark, 1, GETDATE(), GETDATE(), @packageId, @transactionHash
        )
      `);

    await new sql.Request(transaction)
      .input("transactionHash", sql.NVarChar(128), transactionHash)
      .input("userId", sql.UniqueIdentifier, user.Id)
      .input("walletRemark", sql.NVarChar(512), walletRemark)
      .input("amount", sql.Decimal(18, 2), amount)
      .input("savingAmount", sql.Decimal(18, 2), savingAmount)
      .input("businessAmount", sql.Decimal(18, 2), businessAmount)
      .input("investAmount", sql.Decimal(18, 2), investAmount)
      .query(`
        INSERT INTO dbo.WalletConsumptionTransactions (
          TransactionHash, AddressFrom, AddressTo, Fee, FeeAmount, AmountReceive, Amount, AppUserId, Type, Remark, DateCreated
        )
        VALUES (
          @transactionHash, N'Ví Giao Dịch', N'Hệ Thống', 0, 0, -@amount, -@amount, @userId, 5, @walletRemark, GETDATE()
        );

        INSERT INTO dbo.WalletSavingTransactions (
          TransactionHash, AddressFrom, AddressTo, Fee, FeeAmount, AmountReceive, Amount, AppUserId, Type, Remark, DateCreated
        )
        VALUES (
          @transactionHash, N'Hệ Thống', N'Ví Tiết Kiệm', 0, 0, @savingAmount, @savingAmount, @userId, 3, @walletRemark, GETDATE()
        );

        INSERT INTO dbo.WalletBusinessTransactions (
          TransactionHash, AddressFrom, AddressTo, Fee, FeeAmount, AmountReceive, Amount, AppUserId, Type, Remark, DateCreated
        )
        VALUES (
          @transactionHash, N'Hệ Thống', N'Ví Kinh Doanh', 0, 0, @businessAmount, @businessAmount, @userId, 3, @walletRemark, GETDATE()
        );

        INSERT INTO dbo.WalletInvestTransactions (
          TransactionHash, AddressFrom, AddressTo, Fee, FeeAmount, AmountReceive, Amount, AppUserId, Type, Remark, DateCreated
        )
        VALUES (
          @transactionHash, N'Hệ Thống', N'Ví Đầu Tư', 0, 0, @investAmount, @investAmount, @userId, 3, @walletRemark, GETDATE()
        );
      `);

    const updatedUserResult = await new sql.Request(transaction)
      .input("userId", sql.UniqueIdentifier, user.Id)
      .query(`
        SELECT TOP 1
          Id,
          UserName,
          Email,
          ConsumptionBalance,
          AffiliateBalance,
          AccumulateBalance,
          SavingBalance,
          BusinessBalance,
          InvestBalance
        FROM dbo.Users
        WHERE Id = @userId
      `);

    await transaction.commit();

    return res.json({
      isSuccess: true,
      message: "Kích hoạt gói đầu tư thành công",
      result: {
        transactionHash,
        project: formatProjectRow(project),
        investPackage: formatInvestPackageRow(investPackage),
        amounts: {
          consumption: -amount,
          saving: savingAmount,
          business: businessAmount,
          invest: investAmount
        },
        user: buildUserResult(updatedUserResult.recordset[0])
      }
    });
  } catch (err) {
    if (transaction._aborted !== true) {
      try {
        await transaction.rollback();
      } catch (_rollbackErr) {
        // Ignore rollback error if transaction already closed.
      }
    }
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.post("/local-api/wallets/consumption/transfer", authMiddleware, async (req, res) => {
  const transaction = new sql.Transaction(await getPool());

  try {
    const recipientAddress = toAddress(req.body.toAddress);
    const amount = parsePositiveAmount(req.body.amount);
    const remark = String(req.body.remark || "").trim();

    if (!recipientAddress) {
      return res.status(400).json({ isSuccess: false, message: "Thiếu địa chỉ nhận" });
    }
    if (!isGuid(recipientAddress)) {
      return res.status(400).json({ isSuccess: false, message: "Địa chỉ nhận không đúng định dạng" });
    }
    if (!amount) {
      return res.status(400).json({ isSuccess: false, message: "Số lượng chuyển không hợp lệ" });
    }

    await transaction.begin(sql.ISOLATION_LEVEL.SERIALIZABLE);

    const senderResult = await new sql.Request(transaction)
      .input("id", sql.UniqueIdentifier, req.auth.sub)
      .query(`
        SELECT TOP 1 Id, UserName, Email, ConsumptionBalance, AffiliateBalance, AccumulateBalance, SavingBalance, BusinessBalance
        FROM dbo.Users WITH (UPDLOCK, ROWLOCK)
        WHERE Id = @id
      `);
    const sender = senderResult.recordset[0];
    if (!sender) {
      await transaction.rollback();
      return res.status(404).json({ isSuccess: false, message: "Không tìm thấy tài khoản gửi" });
    }

    const senderAddress = toAddress(sender.Id);
    if (senderAddress === recipientAddress) {
      await transaction.rollback();
      return res.status(400).json({ isSuccess: false, message: "Không thể chuyển cho chính mình" });
    }

    const recipientResult = await new sql.Request(transaction)
      .input("lookupAddress", sql.UniqueIdentifier, recipientAddress)
      .query(`
        SELECT TOP 1 Id, UserName, Email, ConsumptionBalance, AffiliateBalance, AccumulateBalance, SavingBalance, BusinessBalance
        FROM dbo.Users WITH (UPDLOCK, ROWLOCK)
        WHERE Id = @lookupAddress
      `);
    const recipient = recipientResult.recordset[0];
    if (!recipient) {
      await transaction.rollback();
      return res.status(404).json({ isSuccess: false, message: "Địa chỉ nhận không tồn tại" });
    }

    if (toNumber(sender.ConsumptionBalance) < amount) {
      await transaction.rollback();
      return res.status(400).json({ isSuccess: false, message: "Số dư ví giao dịch không đủ" });
    }

    const transactionHash = crypto.randomUUID().replace(/-/g, "");
    const senderType = 3;
    const recipientType = 4;
    const finalRemark = remark || "Chuyen vi giao dich";
    const senderDisplay = sender.Email || sender.UserName || senderAddress;
    const recipientDisplay = recipient.Email || recipient.UserName || recipientAddress;

    await new sql.Request(transaction)
      .input("amount", sql.Decimal(18, 2), amount)
      .input("senderId", sql.UniqueIdentifier, sender.Id)
      .query(`
        UPDATE dbo.Users
        SET ConsumptionBalance = ISNULL(ConsumptionBalance, 0) - @amount,
            ModifiedOn = GETDATE()
        WHERE Id = @senderId
      `);

    await new sql.Request(transaction)
      .input("amount", sql.Decimal(18, 2), amount)
      .input("recipientId", sql.UniqueIdentifier, recipient.Id)
      .query(`
        UPDATE dbo.Users
        SET ConsumptionBalance = ISNULL(ConsumptionBalance, 0) + @amount,
            ModifiedOn = GETDATE()
        WHERE Id = @recipientId
      `);

    await new sql.Request(transaction)
      .input("transactionHash", sql.NVarChar(128), transactionHash)
      .input("addressFrom", sql.NVarChar(256), senderDisplay)
      .input("addressTo", sql.NVarChar(256), recipientDisplay)
      .input("amount", sql.Decimal(18, 2), amount)
      .input("amountReceive", sql.Decimal(18, 2), amount)
      .input("senderId", sql.UniqueIdentifier, sender.Id)
      .input("recipientId", sql.UniqueIdentifier, recipient.Id)
      .input("senderType", sql.Int, senderType)
      .input("recipientType", sql.Int, recipientType)
      .input("senderRemark", sql.NVarChar(512), `${senderDisplay} chuyển ${amount.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} Vntd đến ${recipientDisplay}${remark ? ` - ${remark}` : ""}`)
      .input("recipientRemark", sql.NVarChar(512), `${senderDisplay} chuyển ${amount.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} Vntd đến ${recipientDisplay}${remark ? ` - ${remark}` : ""}`)
      .query(`
        INSERT INTO dbo.WalletConsumptionTransactions (
          TransactionHash, AddressFrom, AddressTo, Fee, FeeAmount, AmountReceive, Amount, AppUserId, Type, Remark, DateCreated
        )
        VALUES (
          @transactionHash, @addressFrom, @addressTo, 0, 0, @amountReceive, @amount, @senderId, @senderType, @senderRemark, GETDATE()
        );

        INSERT INTO dbo.WalletConsumptionTransactions (
          TransactionHash, AddressFrom, AddressTo, Fee, FeeAmount, AmountReceive, Amount, AppUserId, Type, Remark, DateCreated
        )
        VALUES (
          @transactionHash, @addressFrom, @addressTo, 0, 0, @amountReceive, @amount, @recipientId, @recipientType, @recipientRemark, GETDATE()
        );
      `);

    const updatedSenderResult = await new sql.Request(transaction)
      .input("id", sql.UniqueIdentifier, sender.Id)
      .query(`
        SELECT TOP 1 Id, UserName, Email, ConsumptionBalance, AffiliateBalance, AccumulateBalance, SavingBalance, BusinessBalance
        FROM dbo.Users
        WHERE Id = @id
      `);

    await transaction.commit();

    return res.json({
      isSuccess: true,
      message: "Chuyển điểm thành công",
      result: {
        transactionHash,
        amount,
        toAddress: recipientAddress,
        recipient: {
          id: String(recipient.Id),
          email: recipient.Email || "",
          userName: recipient.UserName || "",
          receiveAddress: recipientAddress
        },
        user: buildUserResult(updatedSenderResult.recordset[0])
      }
    });
  } catch (err) {
    if (transaction._aborted !== true) {
      try {
        await transaction.rollback();
      } catch (_rollbackErr) {
        // Ignore rollback error if the transaction has already failed closed.
      }
    }
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.post("/local-api/wallets/accumulate/withdraw-0-2", authMiddleware, async (req, res) => {
  const transaction = new sql.Transaction(await getPool());
  const percent = 0.002; // 0.2%

  try {
    await transaction.begin(sql.ISOLATION_LEVEL.SERIALIZABLE);

    const userResult = await new sql.Request(transaction)
      .input("id", sql.UniqueIdentifier, req.auth.sub)
      .query(`
        SELECT TOP 1 Id, UserName, Email, AccumulateBalance, ConsumptionBalance
        FROM dbo.Users WITH (UPDLOCK, ROWLOCK)
        WHERE Id = @id
      `);
    const user = userResult.recordset[0];
    if (!user) {
      await transaction.rollback();
      return res.status(404).json({ isSuccess: false, message: "Không tìm thấy tài khoản" });
    }

    const amount = calcPercent(user.AccumulateBalance, percent);
    if (!amount) {
      await transaction.rollback();
      return res.status(400).json({ isSuccess: false, message: "Số dư ví tích điểm không đủ để rút 0.2%" });
    }

    const transactionHash = crypto.randomUUID().replace(/-/g, "");
    const remark = `${user.Email || user.UserName || "Người dùng"} hoán đổi 0.2% tương đương ${formatMoneyEn(amount)} Vntd từ ví Tích Điểm đến ví Giao Dịch`;

    await new sql.Request(transaction)
      .input("userId", sql.UniqueIdentifier, user.Id)
      .input("amount", sql.Decimal(18, 2), amount)
      .query(`
        UPDATE dbo.Users
        SET AccumulateBalance = ISNULL(AccumulateBalance, 0) - @amount,
            ConsumptionBalance = ISNULL(ConsumptionBalance, 0) + @amount,
            ModifiedOn = GETDATE()
        WHERE Id = @userId
      `);

    await new sql.Request(transaction)
      .input("transactionHash", sql.NVarChar(128), transactionHash)
      .input("addressFrom", sql.NVarChar(256), "Ví Tích Điểm")
      .input("addressTo", sql.NVarChar(256), "Ví Giao Dịch")
      .input("amount", sql.Decimal(18, 2), -amount)
      .input("remark", sql.NVarChar(512), remark)
      .input("userId", sql.UniqueIdentifier, user.Id)
      .query(`
        INSERT INTO dbo.WalletAccumulateTransactions (
          TransactionHash, AddressFrom, AddressTo, Fee, FeeAmount, AmountReceive, Amount, AppUserId, Type, Remark, DateCreated
        ) VALUES (
          @transactionHash, @addressFrom, @addressTo, 0, 0, @amount, @amount, @userId, 4, @remark, GETDATE()
        );
      `);

    await new sql.Request(transaction)
      .input("transactionHash", sql.NVarChar(128), transactionHash)
      .input("addressFrom", sql.NVarChar(256), "Ví Tích Điểm")
      .input("addressTo", sql.NVarChar(256), "Ví Giao Dịch")
      .input("amount", sql.Decimal(18, 2), amount)
      .input("remark", sql.NVarChar(512), remark)
      .input("userId", sql.UniqueIdentifier, user.Id)
      .query(`
        INSERT INTO dbo.WalletConsumptionTransactions (
          TransactionHash, AddressFrom, AddressTo, Fee, FeeAmount, AmountReceive, Amount, AppUserId, Type, Remark, DateCreated
        ) VALUES (
          @transactionHash, @addressFrom, @addressTo, 0, 0, @amount, @amount, @userId, 7, @remark, GETDATE()
        );
      `);

    const updated = await new sql.Request(transaction)
      .input("id", sql.UniqueIdentifier, user.Id)
      .query("SELECT TOP 1 Id, UserName, Email, ConsumptionBalance, AffiliateBalance, AccumulateBalance, SavingBalance, BusinessBalance, InvestBalance FROM dbo.Users WHERE Id = @id");

    await transaction.commit();

    return res.json({
      isSuccess: true,
      message: "Đã rút 0.2% từ ví Tích Điểm về ví Giao Dịch",
      result: {
        amount,
        transactionHash,
        user: buildUserResult(updated.recordset[0])
      }
    });
  } catch (err) {
    if (transaction._aborted !== true) {
      try { await transaction.rollback(); } catch (_e) {}
    }
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.post("/local-api/wallets/saving/withdraw-0-2", authMiddleware, async (req, res) => {
  const transaction = new sql.Transaction(await getPool());
  const percent = 0.002; // 0.2%

  try {
    await transaction.begin(sql.ISOLATION_LEVEL.SERIALIZABLE);

    const userResult = await new sql.Request(transaction)
      .input("id", sql.UniqueIdentifier, req.auth.sub)
      .query(`
        SELECT TOP 1 Id, UserName, Email, SavingBalance, ConsumptionBalance
        FROM dbo.Users WITH (UPDLOCK, ROWLOCK)
        WHERE Id = @id
      `);
    const user = userResult.recordset[0];
    if (!user) {
      await transaction.rollback();
      return res.status(404).json({ isSuccess: false, message: "Không tìm thấy tài khoản" });
    }

    const amount = calcPercent(user.SavingBalance, percent);
    if (!amount) {
      await transaction.rollback();
      return res.status(400).json({ isSuccess: false, message: "Số dư ví tiết kiệm không đủ để rút 0.2%" });
    }

    const transactionHash = crypto.randomUUID().replace(/-/g, "");
    const remark = `${user.Email || user.UserName || "Người dùng"} hoán đổi 0.2% tương đương ${formatMoneyEn(amount)} Vntd từ ví Tiết Kiệm đến ví Giao Dịch`;

    await new sql.Request(transaction)
      .input("userId", sql.UniqueIdentifier, user.Id)
      .input("amount", sql.Decimal(18, 2), amount)
      .query(`
        UPDATE dbo.Users
        SET SavingBalance = ISNULL(SavingBalance, 0) - @amount,
            ConsumptionBalance = ISNULL(ConsumptionBalance, 0) + @amount,
            ModifiedOn = GETDATE()
        WHERE Id = @userId
      `);

    await new sql.Request(transaction)
      .input("transactionHash", sql.NVarChar(128), transactionHash)
      .input("addressFrom", sql.NVarChar(256), "Ví Tiết Kiệm")
      .input("addressTo", sql.NVarChar(256), "Ví Giao Dịch")
      .input("amount", sql.Decimal(18, 2), -amount)
      .input("remark", sql.NVarChar(512), remark)
      .input("userId", sql.UniqueIdentifier, user.Id)
      .query(`
        INSERT INTO dbo.WalletSavingTransactions (
          TransactionHash, AddressFrom, AddressTo, Fee, FeeAmount, AmountReceive, Amount, AppUserId, Type, Remark, DateCreated
        ) VALUES (
          @transactionHash, @addressFrom, @addressTo, 0, 0, @amount, @amount, @userId, 5, @remark, GETDATE()
        );
      `);

    await new sql.Request(transaction)
      .input("transactionHash", sql.NVarChar(128), transactionHash)
      .input("addressFrom", sql.NVarChar(256), "Ví Tiết Kiệm")
      .input("addressTo", sql.NVarChar(256), "Ví Giao Dịch")
      .input("amount", sql.Decimal(18, 2), amount)
      .input("remark", sql.NVarChar(512), remark)
      .input("userId", sql.UniqueIdentifier, user.Id)
      .query(`
        INSERT INTO dbo.WalletConsumptionTransactions (
          TransactionHash, AddressFrom, AddressTo, Fee, FeeAmount, AmountReceive, Amount, AppUserId, Type, Remark, DateCreated
        ) VALUES (
          @transactionHash, @addressFrom, @addressTo, 0, 0, @amount, @amount, @userId, 6, @remark, GETDATE()
        );
      `);

    const updated = await new sql.Request(transaction)
      .input("id", sql.UniqueIdentifier, user.Id)
      .query("SELECT TOP 1 Id, UserName, Email, ConsumptionBalance, AffiliateBalance, AccumulateBalance, SavingBalance, BusinessBalance, InvestBalance FROM dbo.Users WHERE Id = @id");

    await transaction.commit();

    return res.json({
      isSuccess: true,
      message: "Đã rút 0.2% từ ví Tiết Kiệm về ví Giao Dịch",
      result: {
        amount,
        transactionHash,
        user: buildUserResult(updated.recordset[0])
      }
    });
  } catch (err) {
    if (transaction._aborted !== true) {
      try { await transaction.rollback(); } catch (_e) {}
    }
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.post("/local-api/users/VerifyRegistration", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const code = String(req.body.code || "").trim();
    if (!email || !code) {
      return res.status(400).json({ isSuccess: false, message: "Thiếu email hoặc mã xác thực" });
    }

    const pool = await getPool();
    const userResult = await pool
      .request()
      .input("normalizedEmail", sql.NVarChar(256), normalize(email))
      .query(`
        SELECT TOP 1
          Id,
          UserName,
          Email,
          EmailConfirmed,
          ConsumptionBalance,
          AffiliateBalance,
          AccumulateBalance,
          SavingBalance,
          BusinessBalance,
          InvestBalance
        FROM dbo.Users
        WHERE UPPER(ISNULL(Email, '')) = @normalizedEmail
           OR UPPER(ISNULL(NormalizedEmail, '')) = @normalizedEmail
      `);
    const user = userResult.recordset[0];
    if (!user) {
      return res.status(404).json({ isSuccess: false, message: "Không tìm thấy tài khoản" });
    }
    if (user.EmailConfirmed) {
      return res.json({
        isSuccess: true,
        message: "Tài khoản đã được xác thực trước đó",
        result: buildUserResult(user)
      });
    }

    const tokenRow = await getUserToken(user.Id, EMAIL_VERIFICATION_PROVIDER, EMAIL_VERIFICATION_TOKEN_NAME);
    const tokenPayload = parseVerificationPayload(tokenRow && tokenRow.Value);
    if (!tokenPayload || tokenPayload.type !== "email_verification") {
      return res.status(404).json({ isSuccess: false, message: "Không tìm thấy yêu cầu xác thực còn hiệu lực" });
    }

    const expiresAt = new Date(tokenPayload.expiresAt || "");
    if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() < Date.now()) {
      await deleteUserToken(user.Id, EMAIL_VERIFICATION_PROVIDER, EMAIL_VERIFICATION_TOKEN_NAME);
      return res.status(410).json({ isSuccess: false, message: "Mã xác thực đã hết hạn" });
    }

    if (hashVerificationValue(code) !== tokenPayload.hash) {
      return res.status(400).json({ isSuccess: false, message: "Mã xác thực không đúng" });
    }

    await pool
      .request()
      .input("id", sql.UniqueIdentifier, user.Id)
      .query(`
        UPDATE dbo.Users
        SET EmailConfirmed = 1,
            ModifiedOn = GETDATE()
        WHERE Id = @id
      `);

    await deleteUserToken(user.Id, EMAIL_VERIFICATION_PROVIDER, EMAIL_VERIFICATION_TOKEN_NAME);

    const verifiedUser = await getUserById(user.Id);
    return res.json({
      isSuccess: true,
      message: "Xác thực tài khoản thành công",
      result: buildUserResult(verifiedUser)
    });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.post("/local-api/users/ResendVerification", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    if (!email) {
      return res.status(400).json({ isSuccess: false, message: "Thiếu email" });
    }

    const pool = await getPool();
    const userResult = await pool
      .request()
      .input("normalizedEmail", sql.NVarChar(256), normalize(email))
      .query(`
        SELECT TOP 1 Id, UserName, Email, EmailConfirmed
        FROM dbo.Users
        WHERE UPPER(ISNULL(Email, '')) = @normalizedEmail
           OR UPPER(ISNULL(NormalizedEmail, '')) = @normalizedEmail
      `);
    const user = userResult.recordset[0];
    if (!user) {
      return res.status(404).json({ isSuccess: false, message: "Không tìm thấy tài khoản" });
    }
    if (user.EmailConfirmed) {
      return res.status(400).json({ isSuccess: false, message: "Tài khoản đã được xác thực" });
    }

    const verification = await issueEmailVerification(user);
    return res.json({
      isSuccess: true,
      message: "Đã tạo lại mã xác thực",
      result: {
        email,
        verificationExpiresAt: verification.expiresAt,
        verificationLink: EMAIL_VERIFICATION_DEBUG ? verification.verificationLink : "",
        debugCode: EMAIL_VERIFICATION_DEBUG ? verification.code : ""
      }
    });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.post("/local-api/users/Register", async (req, res) => {
  try {
    const host = String(req.headers.host || "").toLowerCase();
    const isLocalHost = /localhost|127\.0\.0\.1/.test(host);
    if (isLocalHost && !ALLOW_LOCAL_REGISTER) {
      return res.status(403).json({ isSuccess: false, message: "Đăng ký chỉ cho phép khi chạy online. Bật ALLOW_LOCAL_REGISTER=true nếu muốn test offline." });
    }

    const payload = req.body && req.body.user ? req.body : { user: req.body, password: req.body.password };
    const userInput = payload.user || {};
    const email = String(userInput.email || userInput.userName || "").trim().toLowerCase();
    const password = String(payload.password || "").trim();
    if (!email || !password) {
      return res.status(400).json({ isSuccess: false, message: "Thiếu email hoặc mật khẩu" });
    }

    const pool = await getPool();
    const check = await pool
      .request()
      .input("normalizedEmail", sql.NVarChar(256), normalize(email))
      .query("SELECT TOP 1 Id FROM dbo.Users WHERE UPPER(ISNULL(Email,''))=@normalizedEmail OR UPPER(ISNULL(NormalizedEmail,''))=@normalizedEmail");
    if (check.recordset.length > 0) {
      return res.status(409).json({ isSuccess: false, message: "Email đã tồn tại" });
    }

    const userName = String(userInput.userName || email).trim();
    const fullName = String(userInput.fullName || userName).trim();
    const phone = String(userInput.phoneNumber || "").trim();
    const referenceEmail = String(userInput.referenceEmail || "").trim();
    const id = crypto.randomUUID();
    const passwordHash = hashAspNetIdentityV3(password);
    const securityStamp = crypto.randomUUID();
    const concurrencyStamp = crypto.randomUUID();

    let referralId = null;
    if (referenceEmail) {
      const ref = await pool
        .request()
        .input("refEmail", sql.NVarChar(256), normalize(referenceEmail))
        .query("SELECT TOP 1 Id FROM dbo.Users WHERE UPPER(ISNULL(Email,''))=@refEmail");
      if (ref.recordset[0] && ref.recordset[0].Id) {
        referralId = ref.recordset[0].Id;
      }
    }

    await pool
      .request()
      .input("id", sql.UniqueIdentifier, id)
      .input("referralId", sql.UniqueIdentifier, referralId)
      .input("referenceEmail", sql.VarChar(255), referenceEmail || null)
      .input("fullName", sql.NVarChar(255), fullName || null)
      .input("userName", sql.NVarChar(256), userName)
      .input("normalizedUserName", sql.NVarChar(256), normalize(userName))
      .input("email", sql.NVarChar(256), email)
      .input("normalizedEmail", sql.NVarChar(256), normalize(email))
      .input("passwordHash", sql.NVarChar(sql.MAX), passwordHash)
      .input("securityStamp", sql.NVarChar(256), securityStamp)
      .input("concurrencyStamp", sql.NVarChar(256), concurrencyStamp)
      .input("phone", sql.NVarChar(50), phone || null)
      .input("emailConfirmed", sql.Bit, EMAIL_VERIFICATION_REQUIRED ? 0 : 1)
      .query(`
        INSERT INTO dbo.Users (
          Id, ReferralId, ReferenceEmail, Fullname,
          UserName, NormalizedUserName, Email, NormalizedEmail,
          EmailConfirmed, PasswordHash,
          ConsumptionBalance, AccumulateBalance, AffiliateBalance, SavingBalance, BusinessBalance, InvestBalance,
          IsRejectBonusCondition, SecurityStamp, ConcurrencyStamp,
          PhoneNumber, PhoneNumberConfirmed, TwoFactorEnabled, LockoutEnabled, AccessFailedCount,
          Status, CreatedOn, ModifiedOn, IsSync
        )
        VALUES (
          @id, @referralId, @referenceEmail, @fullName,
          @userName, @normalizedUserName, @email, @normalizedEmail,
          @emailConfirmed, @passwordHash,
          0, 0, 0, 0, 0, 0,
          0, @securityStamp, @concurrencyStamp,
          @phone, 0, 0, 0, 0,
          1, GETDATE(), GETDATE(), 0
        )
      `);

    let verification = null;
    if (EMAIL_VERIFICATION_REQUIRED) {
      verification = await issueEmailVerification({ Id: id, Email: email });
    }

    return res.json({
      isSuccess: true,
      message: EMAIL_VERIFICATION_REQUIRED
        ? "Đăng ký thành công. Vui lòng xác thực email trước khi đăng nhập"
        : "Đăng ký thành công",
      result: {
        id,
        email,
        userName,
        receiveAddress: toAddress(id),
        emailConfirmed: !EMAIL_VERIFICATION_REQUIRED,
        requiresVerification: EMAIL_VERIFICATION_REQUIRED,
        verificationExpiresAt: verification ? verification.expiresAt : null,
        verificationLink: verification && EMAIL_VERIFICATION_DEBUG ? verification.verificationLink : "",
        debugCode: verification && EMAIL_VERIFICATION_DEBUG ? verification.code : ""
      }
    });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.use(express.static(path.resolve(__dirname)));

app.get("/", (_req, res) => {
  res.sendFile(path.resolve(__dirname, "index.html"));
});

app.listen(PORT, HOST, async () => {
  try {
    await getPool();
    console.log(`[local-api] ready on http://${HOST}:${PORT}`);
    console.log(`[local-api] db=${dbConfig.server}:${dbConfig.port}/${dbConfig.database}`);
  } catch (err) {
    console.error("[local-api] DB connection failed:", err.message);
  }
});
