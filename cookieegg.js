// cookieegg.js — Silenced long auth logs + robust party auto-accept with retries
// NOTE: these documents can only be used in code execution

const mineflayer = require('mineflayer');
const Vec3 = require('vec3');
const { SocksClient } = require('socks');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { pathToFileURL } = require('url');

// =================== Config ===================
const COOKIES_DIR = path.resolve(__dirname, 'profilesss');   // Netscape cookie exports
const PROXIES_FILE = path.resolve(__dirname, 'proxies.txt'); // host:port:user:pass per line
const SERVER_HOST = 'mc.hypixel.net';
const SERVER_PORT = 25565;
const MC_VERSION = '1.8.9';

// Controlled concurrency
const CONCURRENCY = 2;
const BETWEEN_BATCH_MS = 1500;

// Target/Party configs
const targetign = 'TheCringers';
const anticallout = false;
const DeadLobbyPlayerCount = 35;
const lobbyFinderIgn = "Bot that you /p transfer to to start finding a lobby's IGN";

// =================== Logging: mask + truncate ===================
const MAX_LOG_STR_LEN = 600; // hard cap for any string segment
function maskSecrets(s) {
  try {
    let out = String(s);
    // Mask user:pass in URLs
    out = out.replace(/:\/\/([^:@/]+):([^@/]+)@/g, '://***:***@');
    // Generic long tokens/base64: collapse centers
    out = out.replace(/([A-Za-z0-9._~-]{40,})/g, (m) => m.slice(0, 10) + '…' + m.slice(-6));
    return out;
  } catch {
    return s;
  }
}
function capString(s, max = MAX_LOG_STR_LEN) {
  const str = String(s);
  if (str.length <= max) return str;
  return str.slice(0, max) + ` …(+${str.length - max} chars)`;
}
function safeStringify(obj, max = MAX_LOG_STR_LEN) {
  let s;
  try { s = JSON.stringify(obj); } catch { s = String(obj); }
  return capString(maskSecrets(s), max);
}
function logMasked(...args) {
  const out = args.map(a => {
    if (typeof a === 'string') return capString(maskSecrets(a));
    return a;
  });
  console.log(...out);
}
// Optional: silence specific tags entirely
const SILENCE_TAGS = new Set(['[auth-debug]']); // fully mute these tags
function logTagged(tag, ...rest) {
  if (SILENCE_TAGS.has(tag)) return;
  logMasked(tag, ...rest);
}

// =================== Banner ===================
console.log('Huys Pit Bots v1.0.7 (discord.gg/huys)');

// =================== Readline (kept minimal) ===================
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
let messageLogged = false;
rl.on('line', () => { messageLogged = false; });

// =================== File helpers ===================
function parseProxyLine(line) {
  if (!line) return null;
  const s = String(line).trim();
  if (!s) return null;
  if (/^(socks5|http|https):\/\//i.test(s)) {
    try {
      const u = new URL(s);
      return {
        scheme: u.protocol.replace(':', ''),
        username: decodeURIComponent(u.username || ''),
        password: decodeURIComponent(u.password || ''),
        host: u.hostname,
        port: u.port
      };
    } catch {
      return null;
    }
  }
  const m = s.match(/^([^:]+):(\d+):([^:]+):(.+)$/);
  if (m) {
    const [, host, port, user, pass] = m;
    return { scheme: 'raw', username: user, password: pass, host, port };
  }
  return null;
}
function toAuthHttpUrl(p) {
  if (!p) return null;
  if (p.scheme === 'http' || p.scheme === 'https') {
    return `${p.scheme}://${encodeURIComponent(p.username)}:${encodeURIComponent(p.password)}@${p.host}:${p.port}`;
  }
  return `http://${encodeURIComponent(p.username)}:${encodeURIComponent(p.password)}@${p.host}:${p.port}`;
}
function readProxies() {
  if (!fs.existsSync(PROXIES_FILE)) return [];
  const lines = fs.readFileSync(PROXIES_FILE, 'utf8').split(/\r?\n/).map(l => l.trim()).filter(Boolean).filter(l => !l.startsWith('#'));
  return lines.map(parseProxyLine).filter(Boolean);
}
function listCookieFiles() {
  if (!fs.existsSync(COOKIES_DIR)) return [];
  return fs.readdirSync(COOKIES_DIR).filter(f => f.toLowerCase().endsWith('.txt')).map(f => path.join(COOKIES_DIR, f));
}
function ensureDir(p) { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true }); }

// =================== Microsoft auth bridge (ESM) ===================
async function cookieFileToProfileDir(cookiePath, authProxyLine) {
  const esmPath = path.join(__dirname, 'microsoftauth.mjs');
  const mod = await import(pathToFileURL(esmPath).href);

  const parsed = parseProxyLine(authProxyLine);
  const httpUrl = parsed ? toAuthHttpUrl(parsed) : null;
  if (httpUrl && mod.setAuthProxyHttpUrl) {
    // Mute or compact these logs
    // logTagged('[auth-debug]', `HTTP(S) proxy for undici via ${httpUrl.replace(/:\/\/[^@]+@/, '://***@')}`);
    // Keep fully silent due to SILENCE_TAGS including [auth-debug]
    mod.setAuthProxyHttpUrl(httpUrl);
  }

  const raw = fs.readFileSync(cookiePath, 'utf8');
  const lines = raw.split(/\r?\n/);

  const ign = await mod.getUsername(lines, null);
  if (!ign) throw new Error('Failed to resolve username via microsoftauth');

  const profileDir = path.join('profiles', ign);
  ensureDir(profileDir);
  return { ign, profileDir };
}

// =================== Ban detection ===================
const bannedAccounts = new Set();
function isHypixelBan(reasonJson) {
  const r = JSON.stringify(reasonJson || '').toLowerCase();
  return (
    r.includes('temporarily banned') ||
    r.includes('permanently banned') ||
    r.includes('security-block') ||
    r.includes('your account has been blocked') ||
    r.includes('block id:') ||
    r.includes('ban id:') ||
    r.includes('hypixel.net/security-block') ||
    r.includes('hypixel.net/appeal')
  );
}

// =================== Bot creation/retry ===================
async function createBotWithRetry(createOpts, attempt = 1) {
  try {
    const bot = mineflayer.createBot(createOpts());
    return bot;
  } catch (e) {
    const msg = e?.message || String(e);
    if (/too fast|try again later|429/i.test(msg)) {
      const wait = Math.min(120000, 5000 * attempt);
      logMasked(`[auth] Rate limited. Retrying in ${wait / 1000}s...`);
      await new Promise(r => setTimeout(r, wait));
      return createBotWithRetry(createOpts, attempt + 1);
    }
    throw e;
  }
}
function scheduleReconnect(account, reason) {
  if (bannedAccounts.has(account.username)) {
    logMasked(`[reconnect-skip] ${account.username} is banned. Not reconnecting.`);
    return;
  }
  const delay = 3000 + Math.floor(Math.random() * 4000);
  logMasked(`[reconnect] ${account.username} in ${delay}ms. Reason: ${reason}`);
  setTimeout(async () => {
    try {
      const b = await createBotWithRetry(account.createOpts);
      wireBotHandlers(b, account);
    } catch (e) {
      logMasked(`[reconnect-fail] ${account.username}: ${e?.message || e}`);
      scheduleReconnect(account, 'retry-fail');
    }
  }, delay);
}

// =================== Chat JSON helpers ===================
function jsonToPlainText(j) {
  try {
    if (!j) return '';
    if (typeof j === 'string') return j;
    if (j.text) return (j.text || '') + (Array.isArray(j.extra) ? j.extra.map(jsonToPlainText).join('') : '');
    if (Array.isArray(j)) return j.map(jsonToPlainText).join('');
    if (j.translate && Array.isArray(j.with)) return j.with.map(jsonToPlainText).join(' ');
    if (j.extra) return (j.extra || []).map(jsonToPlainText).join('');
    return '';
  } catch {
    return '';
  }
}
function traverseJson(node, visit) {
  try {
    if (!node) return;
    if (Array.isArray(node)) { node.forEach(n => traverseJson(n, visit)); return; }
    if (typeof node === 'string') return;
    visit(node);
    if (Array.isArray(node.extra)) node.extra.forEach(n => traverseJson(n, visit));
    if (Array.isArray(node.with)) node.with.forEach(n => traverseJson(n, visit));
    if (Array.isArray(node.siblings)) node.siblings.forEach(n => traverseJson(n, visit));
  } catch {}
}
function extractPartyAcceptCommand(jsonMsg) {
  let cmd = null;
  traverseJson(jsonMsg, (n) => {
    if (cmd) return;
    const ce = n.clickEvent;
    if (ce && (ce.action === 'run_command' || ce.action === 'suggest_command')) {
      const v = String(ce.value || '');
      if (/^\/(p|party)\s+accept\b/i.test(v)) cmd = v.trim();
    }
  });
  return cmd;
}

// =================== Party accept with retries ===================
function wirePartyAutoAccept(bot, targetIGN, accountLabel) {
  const state = {
    joinedParty: false,
    inviteSeenAt: 0,
    retryHandle: null
  };

  function markJoined() {
    state.joinedParty = true;
    if (state.retryHandle) { clearTimeout(state.retryHandle); state.retryHandle = null; }
  }

  function tryAcceptOnce(inviter) {
    if (state.joinedParty) return;
    const name = inviter || targetIGN;
    // Random short delay 300–900ms before accepting
    const delay = 300 + Math.floor(Math.random() * 600);
    setTimeout(() => {
      if (state.joinedParty) return;
      bot.chat(`/p accept ${name}`);
      // Backup try for alternate form and no-name
      setTimeout(() => !state.joinedParty && bot.chat(`/party accept ${name}`), 400 + Math.random() * 500);
      setTimeout(() => !state.joinedParty && bot.chat(`/p accept`), 800 + Math.random() * 500);
    }, delay);
  }

  function scheduleRetries(inviter) {
    if (state.joinedParty) return;
    const now = Date.now();
    // Retry window 12s total with 4 attempts
    const attempts = [1200, 3000, 5200, 8500];
    attempts.forEach(ms => {
      setTimeout(() => tryAcceptOnce(inviter), ms + Math.floor(Math.random() * 250));
    });
    // Safety stop
    setTimeout(() => {
      if (!state.joinedParty) logMasked(`[party] (${accountLabel}) no join confirmation after retries`);
    }, 14000);
  }

  bot.on('message', (json) => {
    const text = jsonToPlainText(json) || '';
    const lower = text.toLowerCase();

    // Detect “You have joined ... party”
    if (/you have joined .* party/i.test(text)) {
      logMasked(`[party] (${accountLabel}) joined party`);
      markJoined();
      return;
    }

    // Detect clickable accept and exact run_command
    const clickCmd = extractPartyAcceptCommand(json);
    if (clickCmd) {
      logMasked(`[party] (${accountLabel}) clickable accept detected -> ${clickCmd.split(/\s+/).slice(0,3).join(' ')}`);
      const parts = clickCmd.trim().split(/\s+/);
      const inviter = parts.length >= 3 ? parts[2] : targetIGN;
      if (!state.inviteSeenAt) state.inviteSeenAt = Date.now();
      tryAcceptOnce(inviter);
      scheduleRetries(inviter);
      return;
    }

    // Fallback: plain text invite line
    // “[IGN] has invited you to join their party!”
    const m = text.match(/^\s*([A-Za-z0-9_]+)\s+has invited you to join their party/i);
    if (m) {
      const inviter = m[1];
      if (!state.inviteSeenAt) state.inviteSeenAt = Date.now();
      logMasked(`[party] (${accountLabel}) plain invite from ${inviter} -> accept`);
      tryAcceptOnce(inviter);
      scheduleRetries(inviter);
    }

    // Time-limited accept line
    if (/you have .* seconds to accept/i.test(lower) || /click here to join/i.test(lower)) {
      if (!state.inviteSeenAt) state.inviteSeenAt = Date.now();
      tryAcceptOnce(targetIGN);
      scheduleRetries(targetIGN);
    }
  });

  // Legacy messagestr support
  bot.on('messagestr', (msg, _pos, jsonMsg) => {
    const m = String(msg || '');
    if (/has invited you to join their party/i.test(m)) {
      const mm = m.match(/^\s*([A-Za-z0-9_]+)\s+has invited you to join their party/i);
      const inviter = mm ? mm[1] : targetIGN;
      if (!state.inviteSeenAt) state.inviteSeenAt = Date.now();
      logMasked(`[party] (${accountLabel}) messagestr invite from ${inviter} -> accept`);
      tryAcceptOnce(inviter);
      scheduleRetries(inviter);
    }
    if (jsonMsg && !state.joinedParty) {
      const clickCmd = extractPartyAcceptCommand(jsonMsg);
      if (clickCmd) {
        logMasked(`[party] (${accountLabel}) messagestr clickable -> ${clickCmd.split(/\s+/).slice(0,3).join(' ')}`);
        const parts = clickCmd.trim().split(/\s+/);
        const inviter = parts.length >= 3 ? parts[2] : targetIGN;
        tryAcceptOnce(inviter);
        scheduleRetries(inviter);
      }
    }
  });
}

// =================== Global bots ===================
const bots = [];

// =================== Wire handlers ===================
function wireBotHandlers(bot, account) {
  bots.push(bot);

  wirePartyAutoAccept(bot, targetign, account.username);

  bot.on('login', () => {
    logMasked(`${bot.username} Connected`);
  });

  bot.on('kicked', (reason) => {
    logMasked(`[kicked] ${account.username}: ${safeStringify(reason, 400)}`);
    if (isHypixelBan(reason)) {
      if (!bannedAccounts.has(account.username)) {
        bannedAccounts.add(account.username);
        logMasked(`[banned] ${account.username} marked as banned.`);
      }
      return; // do not reconnect on ban
    }
    scheduleReconnect(account, 'kicked');
  });

  bot.on('end', () => {
    logMasked(`[end] ${account.username}`);
    scheduleReconnect(account, 'end');
  });

  bot.on('error', (err) => {
    logMasked(`[error] ${account.username}: ${capString(err?.message || err)}`);
  });

  if (anticallout) {
    bot.on('messagestr', async (message) => {
      if (String(message).toLowerCase().includes('bot')) {
        for (let i = 0; i < 100; i++) {
          await new Promise(r => setTimeout(r, 2));
          bot.chat('/');
        }
      }
    });
  }

  // Minimal movement loop toggled by start/stop commands
  bot.on('physicTick', () => {
    // You can add behavior here if needed
  });
}

// =================== CLI Commands (subset) ===================
rl.on('line', (input) => {
  const [command, ...args] = input.split(' ');

  if (command === 'party') {
    if (!messageLogged) {
      messageLogged = true;
      if (bots.length > 5) {
        for (let i = 0; i < bots.length; i += 5) {
          const botNames = bots.slice(i, i + 5).map(b => b.username).join(' ');
          console.log('/party ' + botNames);
        }
      } else {
        console.log('/party ' + bots.map(b => b.username).join(' '));
      }
    }
  }

  if (command === 'lobby') {
    bots.forEach(b => b.chat('/lobby'));
  }

  if (command === 'play') {
    bots.forEach(b => b.chat('/play pit'));
  }

  if (command === 'limbo') {
    bots.forEach(b => {
      b.chat('/l');
      for (let i = 0; i < 50; i++) setTimeout(() => b.chat('/'), 100);
    });
  }

  if (command === 'run') {
    const msg = args.join(' ');
    bots.forEach(b => b.chat(msg));
  }
});

// =================== Runner: Auth over HTTP, gameplay via SocksClient ===================
function makeConnectWithSocks(proxyParsed, label) {
  if (!proxyParsed) return null;
  const proxyInfo = {
    host: proxyParsed.host,
    port: parseInt(proxyParsed.port, 10),
    type: 5,
    userId: proxyParsed.username || undefined,
    password: proxyParsed.password || undefined
  };
  const destination = { host: SERVER_HOST, port: SERVER_PORT };
  return (botConnection) => {
    logMasked(`[net] ${label} dialing SOCKS5 ${proxyInfo.host}:${proxyInfo.port} -> ${destination.host}:${destination.port}`);
    SocksClient.createConnection({ proxy: proxyInfo, command: 'connect', destination }, (err, info) => {
      if (err) {
        logMasked(`[net-fail] ${label} SOCKS connect error: ${capString(err.message || err)}`);
        botConnection.emit('error', err);
        return;
      }
      botConnection.setSocket(info.socket);
      botConnection.emit('connect');
    });
  };
}

async function main() {
  const proxies = readProxies();
  const cookieFiles = listCookieFiles();

  if (!cookieFiles.length) {
    console.log(`[init] No cookie files in ${COOKIES_DIR}`);
    process.exit(1);
  }
  logMasked(`[init] Found ${cookieFiles.length} cookie files.`);

  for (let i = 0; i < cookieFiles.length; i += CONCURRENCY) {
    const slice = cookieFiles.slice(i, i + CONCURRENCY);

    await Promise.all(slice.map(async (cookiePath, j) => {
      const idx = i + j;
      const proxyParsed = proxies.length ? proxies[idx % proxies.length] : null;

      try {
        const authProxyLine = proxyParsed
          ? `${proxyParsed.host}:${proxyParsed.port}:${proxyParsed.username || ''}:${proxyParsed.password || ''}`
          : null;

        // Silence noisy oauth debug inside microsoftauth by just not logging it here
        const { ign, profileDir } = await cookieFileToProfileDir(cookiePath, authProxyLine);

        ensureDir(profileDir);

        const label = ign;
        const connectFn = makeConnectWithSocks(proxyParsed, label);

        const createOpts = () => {
          const opts = {
            host: SERVER_HOST,
            port: SERVER_PORT,
            version: MC_VERSION,
            auth: 'microsoft',
            profilesFolder: profileDir
          };
          if (connectFn) opts.connect = connectFn;
          return opts;
        };

        logMasked(`[start] ${label} profilesFolder: ${profileDir}` + (proxyParsed ? ` via socks5://${proxyParsed.username ? '***@' : ''}${proxyParsed.host}:${proxyParsed.port}` : ''));

        // Small stagger
        await new Promise(r => setTimeout(r, 600 + Math.floor(Math.random() * 600)));

        const bot = await createBotWithRetry(createOpts);
        wireBotHandlers(bot, { username: label, createOpts });
      } catch (e) {
        logMasked(`[start-fail] ${path.basename(cookiePath)}: ${capString(e?.message || e)}`);
      }
    }));

    if (i + CONCURRENCY < cookieFiles.length) {
      await new Promise(r => setTimeout(r, BETWEEN_BATCH_MS));
    }
  }
}

main().catch(e => {
  console.error('[fatal]', capString(e?.message || e));
  process.exit(1);
});