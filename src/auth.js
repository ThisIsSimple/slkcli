/**
 * Slack auth — extracts session credentials from the Slack desktop app on macOS.
 *
 * Modern Slack desktop sessions require more than a stale xoxc token from LevelDB.
 * This implementation:
 * 1. Reads and decrypts Slack cookies from the desktop app (d/x/b)
 * 2. Finds a real workspace host and team/channel context from local cache
 * 3. Requests the workspace root with the d cookie to obtain a fresh xoxc token
 * 4. Validates the xoxc token with auth.test
 */

import { execSync, spawnSync } from "child_process";
import { readFileSync, readdirSync, copyFileSync, unlinkSync, writeFileSync, existsSync, mkdirSync } from "fs";
import fs from "fs";
import path, { join } from "path";
import { homedir, tmpdir } from "os";
import { pbkdf2Sync } from "crypto";

const SLACK_DIR_DIRECT = join(homedir(), "Library", "Application Support", "Slack");
const SLACK_DIR_APPSTORE = join(
  homedir(),
  "Library", "Containers", "com.tinyspeck.slackmacgap",
  "Data", "Library", "Application Support", "Slack"
);

function resolveSlackDir() {
  if (existsSync(SLACK_DIR_DIRECT)) return SLACK_DIR_DIRECT;
  if (existsSync(SLACK_DIR_APPSTORE)) return SLACK_DIR_APPSTORE;
  console.error(
    "Could not find Slack data directory.\n" +
    "Checked:\n" +
    `  ${SLACK_DIR_DIRECT}\n` +
    `  ${SLACK_DIR_APPSTORE}\n` +
    "Is Slack installed?"
  );
  process.exit(1);
}

const SLACK_DIR = resolveSlackDir();
const COOKIES_DB = join(SLACK_DIR, "Cookies");
const CACHE_DIR = join(homedir(), ".local", "slk");
const TOKEN_CACHE = join(CACHE_DIR, "token-cache.json");

let cachedCreds = null;

function walk(dir) {
  const out = [];
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

function getKeychainKey() {
  const accounts = SLACK_DIR === SLACK_DIR_APPSTORE
    ? ["Slack App Store Key", "Slack Key", "Slack"]
    : ["Slack Key", "Slack", "Slack App Store Key"];

  for (const account of accounts) {
    try {
      return Buffer.from(
        execSync(
          `security find-generic-password -s "Slack Safe Storage" -a "${account}" -w`,
          { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }
        ).trim()
      );
    } catch {}
  }

  console.error("Could not find Slack Safe Storage key in Keychain.");
  process.exit(1);
}

function decryptCookieValue(name) {
  const tmpDb = join(tmpdir(), `slk_cookies_${Date.now()}.db`);
  copyFileSync(COOKIES_DB, tmpDb);

  try {
    const hex = execSync(
      `sqlite3 "${tmpDb}" "SELECT hex(encrypted_value) FROM cookies WHERE name='${name}' AND host_key='.slack.com' LIMIT 1;"`,
      { encoding: "utf-8" }
    ).trim();

    if (!hex) throw new Error(`No '${name}' cookie found in Slack cookie store`);
    const encrypted = Buffer.from(hex, "hex");
    if (encrypted.subarray(0, 3).toString() !== "v10") {
      throw new Error("Unknown cookie encryption format");
    }

    const data = encrypted.subarray(3);
    const aesKey = pbkdf2Sync(getKeychainKey(), "saltysalt", 1003, 16, "sha1");
    const iv = Buffer.alloc(16, " ");
    const tmpEnc = join(tmpdir(), `slk_enc_${Date.now()}.bin`);
    writeFileSync(tmpEnc, data);
    const result = spawnSync("openssl", [
      "enc", "-aes-128-cbc", "-d", "-nopad",
      "-K", aesKey.toString("hex"),
      "-iv", iv.toString("hex"),
      "-in", tmpEnc,
    ]);
    unlinkSync(tmpEnc);

    const decrypted = result.stdout;
    if (!decrypted || decrypted.length === 0) throw new Error("Cookie decryption failed");
    const padLen = decrypted[decrypted.length - 1];
    const unpadded = padLen <= 16 ? decrypted.subarray(0, -padLen) : decrypted;
    return unpadded.toString("utf-8");
  } finally {
    try { unlinkSync(tmpDb); } catch {}
  }
}

function extractCookie(name, text) {
  if (name === "d") {
    const idx = text.indexOf("xoxd-");
    if (idx < 0) throw new Error("No xoxd- found in decrypted d cookie");
    return text.substring(idx);
  }
  const m = text.match(/([a-f0-9]{32}(?:\.\d+)?)/i);
  if (!m) throw new Error(`Could not parse '${name}' cookie value`);
  return m[1];
}

function decryptCookie() {
  return extractCookie("d", decryptCookieValue("d"));
}

function decryptBindingCookies() {
  return {
    d: extractCookie("d", decryptCookieValue("d")),
    x: extractCookie("x", decryptCookieValue("x")),
    b: extractCookie("b", decryptCookieValue("b")),
  };
}

function findWorkspaceContext() {
  const searchDirs = [
    join(SLACK_DIR, "Cache", "Cache_Data"),
    join(SLACK_DIR, "Service Worker", "CacheStorage"),
    join(SLACK_DIR, "Local Storage", "leveldb"),
    join(SLACK_DIR, "Session Storage"),
  ];

  let fallbackTeam = null;
  let fallbackChannel = null;

  for (const dir of searchDirs) {
    if (!existsSync(dir)) continue;
    for (const file of walk(dir)) {
      try {
        const buf = fs.readFileSync(file);
        const content = buf.toString("utf-8");
        const m = content.match(/app\.slack\.com\/client\/([A-Z0-9]+)\/([A-Z0-9]+)/);
        if (m) {
          fallbackTeam = m[1];
          fallbackChannel = m[2];
          return { teamId: fallbackTeam, channelId: fallbackChannel };
        }
      } catch {}
    }
  }

  if (fallbackTeam) return { teamId: fallbackTeam, channelId: fallbackChannel };
  throw new Error("Could not determine Slack team/channel context from local cache");
}

function findWorkspaceHost(cookies, context) {
  const url = `https://app.slack.com/client/${context.teamId}/${context.channelId}`;
  const result = spawnSync("curl", [
    "-sL",
    "-H", `Cookie: d=${cookies.d}; x=${cookies.x}; b=${cookies.b}`,
    url,
  ], { encoding: "utf-8", timeout: 20000 });

  const text = result.stdout || "";
  const matches = [...text.matchAll(/https:\/\/([a-zA-Z0-9-]+)\.slack\.com/g)].map(m => `${m[1]}.slack.com`);
  const host = matches.find(h => h !== "app.slack.com");
  if (!host) throw new Error("Could not determine Slack workspace host from app client bootstrap");
  return host;
}

function fetchTokenFromWorkspace(cookies, host) {
  const result = spawnSync("curl", [
    "-sL",
    "-H", `Cookie: d=${cookies.d}`,
    `https://${host}/`,
  ], { encoding: "utf-8", timeout: 20000 });
  const text = result.stdout || "";
  const tokens = [...text.matchAll(/xoxc-[a-zA-Z0-9-]{40,}/g)].map(m => m[0]);
  if (!tokens.length) {
    throw new Error(`No xoxc token found from workspace bootstrap (${host})`);
  }
  return tokens[0];
}

function loadTokenCache() {
  try {
    if (existsSync(TOKEN_CACHE)) {
      return JSON.parse(readFileSync(TOKEN_CACHE, "utf-8"));
    }
  } catch {}
  return null;
}

function saveTokenCache(token, host) {
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
    writeFileSync(TOKEN_CACHE, JSON.stringify({ token, host, ts: Date.now() }));
  } catch {}
}

function validateToken(token, cookie) {
  try {
    const result = spawnSync("curl", [
      "-s", "https://slack.com/api/auth.test",
      "-H", `Authorization: Bearer ${token}`,
      "-b", `d=${cookie}`,
    ], { encoding: "utf-8", timeout: 10000 });
    const data = JSON.parse(result.stdout || "{}");
    return data.ok ? token : null;
  } catch {
    return null;
  }
}

export function getCredentials(forceRefresh = false) {
  if (cachedCreds && !forceRefresh) return cachedCreds;

  const cookies = decryptBindingCookies();

  if (!forceRefresh) {
    const cache = loadTokenCache();
    const validCached = cache?.token ? validateToken(cache.token, cookies.d) : null;
    if (validCached) {
      cachedCreds = { token: validCached, cookie: cookies.d, host: cache.host || null };
      return cachedCreds;
    }
  }

  const context = findWorkspaceContext();
  const host = findWorkspaceHost(cookies, context);
  const token = fetchTokenFromWorkspace(cookies, host);
  const validToken = validateToken(token, cookies.d);
  if (!validToken) {
    throw new Error("Failed to obtain a valid Slack session token from workspace bootstrap");
  }

  saveTokenCache(validToken, host);
  cachedCreds = { token: validToken, cookie: cookies.d, host };
  return cachedCreds;
}

export function refresh() {
  cachedCreds = null;
  return getCredentials(true);
}
