require("./scripts/load-env");

const crypto = require("crypto");
const path = require("path");

const express = require("express");
const jwt = require("jsonwebtoken");
const sql = require("mssql");

const app = express();

const PORT = Number(process.env.PORT || 8080);
const JWT_SECRET = process.env.JWT_SECRET || "voucherswap-local-secret";
const TOKEN_EXPIRES_SEC = Number(process.env.TOKEN_EXPIRES_SEC || 86400);
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || "*";
const IS_PRODUCTION = process.env.NODE_ENV === "production" || Boolean(process.env.RAILWAY_ENVIRONMENT);

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
        PasswordHash,
        ConsumptionBalance,
        AffiliateBalance,
        AccumulateBalance,
        SavingBalance,
        BusinessBalance
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
        ConsumptionBalance,
        AffiliateBalance,
        AccumulateBalance,
        SavingBalance,
        BusinessBalance
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
    const user = await getUserById(req.auth.sub);
    if (!user) {
      return res.status(404).json({ message: "Không tìm thấy tài khoản" });
    }
    const result = {
      id: String(user.Id),
      userName: user.UserName || "",
      email: user.Email || "",
      consumptionBalance: toNumber(user.ConsumptionBalance),
      affiliateBalance: toNumber(user.AffiliateBalance),
      accumulateBalance: toNumber(user.AccumulateBalance),
      savingBalance: toNumber(user.SavingBalance),
      businessBalance: toNumber(user.BusinessBalance)
    };
    return res.json({ isSuccess: true, result });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.post("/local-api/users/Register", async (req, res) => {
  try {
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
          0, @passwordHash,
          0, 0, 0, 0, 0, 0,
          0, @securityStamp, @concurrencyStamp,
          @phone, 0, 0, 0, 0,
          1, GETDATE(), GETDATE(), 0
        )
      `);

    return res.json({ isSuccess: true, message: "Đăng ký thành công", result: { id, email, userName } });
  } catch (err) {
    return res.status(500).json({ isSuccess: false, message: err.message });
  }
});

app.use(express.static(path.resolve(__dirname)));

app.get("/", (_req, res) => {
  res.sendFile(path.resolve(__dirname, "index.html"));
});

app.listen(PORT, async () => {
  try {
    await getPool();
    console.log(`[local-api] ready on http://localhost:${PORT}`);
    console.log(`[local-api] db=${dbConfig.server}:${dbConfig.port}/${dbConfig.database}`);
  } catch (err) {
    console.error("[local-api] DB connection failed:", err.message);
  }
});
