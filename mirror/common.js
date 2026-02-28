// Simple shared helpers for mirror pages
const cfgKey = "vs-mirror-config";

function loadCfg() {
  const raw = localStorage.getItem(cfgKey);
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return {}; }
}

function saveCfg(data) {
  localStorage.setItem(cfgKey, JSON.stringify(data));
}

function setToken(token) {
  const cfg = loadCfg();
  cfg.token = token;
  saveCfg(cfg);
}

function getToken() {
  return loadCfg().token || "";
}

function getApiBase() {
  return loadCfg().apiBase || "https://api.voucherswap.net/api";
}

function getIdentityBase() {
  return loadCfg().identityBase || "https://identity.voucherswap.net";
}

async function loginWithPassword(email, password) {
  const url = `${getIdentityBase()}/connect/token`;
  const form = new URLSearchParams();
  form.set("Client_Id", "MyClientId");
  form.set("Client_Secret", "");
  form.set("Scope", "MyClientId_api");
  form.set("UserName", email);
  form.set("Password", password);
  form.set("grant_type", "password");

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  if (!res.ok) {
    throw new Error(`Login failed (${res.status})`);
  }
  const json = await res.json();
  if (!json.access_token) throw new Error("No access_token returned");
  setToken(json.access_token);
  return json.access_token;
}

async function fetchUserInfo() {
  const url = `${getApiBase()}/users/GetUserInfo`;
  const token = getToken();
  if (!token) throw new Error("Missing token");
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error(`GetUserInfo failed (${res.status})`);
  }
  const json = await res.json();
  // API returns { isSuccess, result: user }
  return json.result || json;
}

function formatNumber(num) {
  return Number(num || 0).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
