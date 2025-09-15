import { fetch, setGlobalDispatcher, Agent, ProxyAgent } from 'undici';
import fs from 'fs';
import fsExtra from 'fs-extra';
import { URL, pathToFileURL } from 'url';
import net from 'net';
import tls from 'tls';
import path from 'path';

console.log('[auth-debug] microsoftauth.mjs loaded from', import.meta.url);

// ---------- helpers for proxy line parsing ----------
function parseProxyLineWithFlags(line) {
  if (!line) return { raw: null, forceHttp: false };
  const s = String(line).trim();
  if (!s) return { raw: null, forceHttp: false };

  // Split query suffix ?forceHttp=1 that a user might append to force fallback
  let base = s;
  let q = '';
  const qi = s.indexOf('?');
  if (qi >= 0) {
    base = s.slice(0, qi);
    q = s.slice(qi + 1);
  }
  const params = new URLSearchParams(q);
  const forceHttp = params.get('forceHttp') === '1' || params.get('forcehttp') === '1';

  return { raw: base, forceHttp };
}

function detectProxyMode(line) {
  if (!line) return null;
  const s = String(line).trim();
  if (!s) return null;
  if (/^https?:\/\//i.test(s)) {
    return { type: 'http', url: s };
  }
  const parts = s.split(':');
  if (parts.length >= 2) {
    const [host, port, user, pass] = parts;
    return { type: 'socks', host, port: parseInt(port, 10), user, pass };
  }
  return null;
}

function toHttpUrlIfPossible(line) {
  if (!line || /^https?:\/\//i.test(line)) return line;
  const parts = String(line).trim().split(':');
  if (parts.length >= 4) {
    const [host, port, user, pass] = parts;
    return `http://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${host}:${port}`;
  }
  if (parts.length === 2) {
    const [host, port] = parts;
    return `http://${host}:${port}`;
  }
  return null;
}

// Convenience: allow caller to explicitly force HTTP CONNECT for auth
export function setAuthProxyHttpUrl(httpUrl) {
  if (!httpUrl) return;
  try {
    const dispatcher = new ProxyAgent(httpUrl);
    setGlobalDispatcher(dispatcher);
    console.log('[auth-debug] Proxy enabled for microsoftauth.mjs via', httpUrl.replace(/:\/\/([^@]+)@/, '://***@'));
  } catch (e) {
    console.log('[auth-debug] Failed to set HTTP proxy:', e?.message || String(e));
  }
}

// ---------- SOCKS5 dialer with stronger diagnostics ----------
async function socks5Connect({ hostname, port, proxyHost, proxyPort, proxyUser, proxyPass, isTls }) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(proxyPort, proxyHost);
    const fail = (e, stage) => {
      const err = e instanceof Error ? e : new Error(String(e));
      err.message = `[socks5:${stage}] ${err.message}`;
      reject(err);
    };

    const readBytes = (n, cb, stage) => {
      const r = socket.read(n);
      if (r && r.length >= n) return cb(r);
      socket.once('readable', () => {
        try { readBytes(n, cb, stage); } catch (e) { fail(e, stage); }
      });
    };

    socket.once('error', (e) => fail(e, 'socket'));
    socket.setTimeout(15000, () => fail(new Error('timeout'), 'socket-timeout'));

    socket.once('connect', () => {
      try {
        const wantAuth = !!(proxyUser || proxyPass);
        const greeting = wantAuth
          ? Buffer.from([0x05, 0x01, 0x02]) // VER=5, NMETHODS=1, METHOD=0x02 (user/pass)
          : Buffer.from([0x05, 0x01, 0x00]); // no-auth
        socket.write(greeting);

        readBytes(2, (sel) => {
          if (sel[0] !== 0x05) return fail(new Error(`bad version in method select: ${sel[0]}`), 'method-select');
          const meth = sel[1];

          if (wantAuth) {
            if (meth !== 0x02) return fail(new Error(`proxy did not accept username/password method (got 0x${meth.toString(16)})`), 'method-select');
            const user = Buffer.from(proxyUser || '');
            const pass = Buffer.from(proxyPass || '');
            const buf = Buffer.alloc(3 + user.length + pass.length);
            buf[0] = 0x01;
            buf[1] = user.length; user.copy(buf, 2);
            buf[2 + user.length] = pass.length; pass.copy(buf, 3 + user.length);
            socket.write(buf);
            readBytes(2, (authRes) => {
              if (authRes[0] !== 0x01 || authRes[1] !== 0x00) {
                return fail(new Error(`SOCKS5 username/password rejected (ver=${authRes[0]}, status=${authRes[1]})`), 'auth');
              }
              doConnect();
            }, 'auth-reply');
          } else {
            if (meth !== 0x00) return fail(new Error(`proxy requires auth but none provided (method=0x${meth.toString(16)})`), 'method-select');
            doConnect();
          }
        }, 'method-select');

        function doConnect() {
          const hostBuf = Buffer.from(hostname);
          const req = Buffer.alloc(7 + hostBuf.length);
          req[0] = 0x05; // VER
          req[1] = 0x01; // CMD=CONNECT
          req[2] = 0x00; // RSV
          req[3] = 0x03; // ATYP=DOMAIN
          req[4] = hostBuf.length;
          hostBuf.copy(req, 5);
          req.writeUInt16BE(port, 5 + hostBuf.length);
          socket.write(req);

          readBytes(4, (head) => {
            if (head[0] !== 0x05) return fail(new Error(`bad version in connect reply: ${head[0]}`), 'connect-reply');
            const rep = head[1];
            const atyp = head[3];
            if (rep !== 0x00) return fail(new Error(`connect failed code=${rep} (0=ok,1=gen,2=deny,3=net,4=host,5=refused,6=ttl,7=cmd,8=atype)`), 'connect-reply');

            const finish = () => {
              if (isTls) {
                const tlsSocket = tls.connect({ socket, servername: hostname });
                tlsSocket.once('error', (e) => fail(e, 'tls'));
                tlsSocket.setTimeout(15000, () => fail(new Error('tls-timeout'), 'tls'));
                tlsSocket.once('secureConnect', () => resolve(tlsSocket));
              } else {
                resolve(socket);
              }
            };

            if (atyp === 0x01) {
              readBytes(6, () => finish(), 'connect-ipv4-tail');
            } else if (atyp === 0x03) {
              readBytes(1, (lenBuf) => {
                readBytes(lenBuf[0] + 2, () => finish(), 'connect-domain-tail');
              }, 'connect-domain-len');
            } else if (atyp === 0x04) {
              readBytes(18, () => finish(), 'connect-ipv6-tail');
            } else {
              finish();
            }
          }, 'connect-head');
        }
      } catch (e) {
        fail(e, 'wrap');
      }
    });
  });
}

// ---------- undici dispatcher builders ----------
let _lastProxyLineForFallback = null;

function buildDispatcherFromLine(line) {
  const det = detectProxyMode(line);
  if (!det) return null;
  if (det.type === 'http') {
    try {
      const sanitized = det.url.replace(/:\/\/([^@]+)@/, '://***@');
      console.log('[auth-debug] HTTP(S) proxy for undici via', sanitized);
      return new ProxyAgent(det.url);
    } catch (e) {
      console.log('[auth-debug] Failed to build HTTP ProxyAgent:', e?.message || String(e));
      return null;
    }
  }
  const { host, port, user, pass } = det;
  if (!port || !host) {
    console.log('[auth-debug] Invalid SOCKS5 proxy line, expected host:port[:user:pass]');
    return null;
  }
  const agent = new Agent({
    connect: (opts, cb) => {
      const isTls = opts.origin.protocol === 'https:';
      const hostname = opts.origin.hostname;
      const dport = Number(opts.origin.port || (isTls ? 443 : 80));
      socks5Connect({
        hostname,
        port: dport,
        proxyHost: host,
        proxyPort: port,
        proxyUser: user || '',
        proxyPass: pass || '',
        isTls
      }).then(sock => cb(null, sock)).catch(err => cb(err, null));
    }
  });
  return agent;
}

export function setProxyFromLine(proxyLineRaw) {
  const pl = parseProxyLineWithFlags(proxyLineRaw);
  if (!pl.raw) {
    console.log('[auth-debug] No proxy or unparsable proxy line; continuing without proxy');
    return;
  }
  const dispatcher = buildDispatcherFromLine(pl.raw);
  if (!dispatcher) {
    console.log('[auth-debug] Could not build dispatcher from proxy; continuing without proxy');
    return;
  }
  setGlobalDispatcher(dispatcher);
  _lastProxyLineForFallback = pl.forceHttp ? toHttpUrlIfPossible(pl.raw) : pl.raw;
  const det = detectProxyMode(pl.raw);
  if (det?.type === 'http') {
    console.log('[auth-debug] Proxy enabled for microsoftauth.mjs via', det.url.replace(/:\/\/([^@]+)@/, '://***@'));
  } else if (det?.type === 'socks') {
    const authTag = det.user || det.pass ? ' with auth' : '';
    console.log('[auth-debug] SOCKS5 proxy enabled for microsoftauth.mjs via', `${det.host}:${det.port}${authTag}`);
  }
}

// ---------- default headers + fetch wrappers ----------
function defaultHeaders(extra = {}) {
  return {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Encoding': 'identity',
    'Connection': 'keep-alive',
    ...extra
  };
}

async function fetchSafe(jar, url, init = {}, tag = 'fetch') {
  const headers = defaultHeaders(init.headers || {});
  const cookieHeader = jar?.getCookieHeaderFor ? jar.getCookieHeaderFor(url) : '';
  if (cookieHeader) headers['Cookie'] = cookieHeader;

  let lastErr;
  for (let i = 1; i <= 2; i++) {
    try {
      const resp = await fetch(url, { ...init, headers, redirect: 'manual' });
      const setCookies = [];
      for (const [k, v] of resp.headers) {
        if (k.toLowerCase() === 'set-cookie') setCookies.push(v);
      }
      if (setCookies.length && jar?.setCookiesFromResponse) jar.setCookiesFromResponse(url, setCookies);
      console.log(`[auth-debug] ${tag} -> ${resp.status} ${resp.headers.get('location') || ''}`);
      return resp;
    } catch (e) {
      lastErr = e;
      console.log(`[auth-debug] ${tag} failed: ${e?.message || String(e)}`);
      if (e && e.message && e.message.startsWith('[socks5:')) {
        console.log('[auth-debug] socks5-stage:', e.message);
      }
      // if first attempt failed via SOCKS, try HTTP fallback one time
      if (i === 1 && _lastProxyLineForFallback && !/^https?:\/\//i.test(_lastProxyLineForFallback)) {
        const httpLine = toHttpUrlIfPossible(_lastProxyLineForFallback);
        if (httpLine) {
          try {
            console.log('[auth-debug] Switching to HTTP proxy fallback for auth');
            setGlobalDispatcher(new ProxyAgent(httpLine));
          } catch (e2) {
            console.log('[auth-debug] HTTP fallback creation failed:', e2?.message || String(e2));
          }
        }
      }
    }
  }
  throw lastErr;
}

async function postJsonWithRetry(url, payload, headers, tag, attempts = 3) {
  let lastErr;
  for (let i = 1; i <= attempts; i++) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: defaultHeaders(headers || {}),
        body: JSON.stringify(payload),
        redirect: 'manual'
      });
      const status = res.status;
      const text = await res.text();
      if ((status === 429 || status >= 500) && i < attempts) {
        const wait = 700 * i;
        console.log(`[auth-debug] ${tag} HTTP ${status} retrying in ${wait}ms (${i}/${attempts})`);
        await new Promise(r => setTimeout(r, wait));
        continue;
      }
      return { res, status, text };
    } catch (e) {
      lastErr = e;
      console.log(`[auth-debug] ${tag} fetch failed (attempt ${i}/${attempts}): ${e?.message || String(e)}`);
      await new Promise(r => setTimeout(r, 600 * i));
    }
  }
  throw lastErr;
}

// ---------- cookie jar ----------
function parseNetscapeLines(lines) {
  const out = [];
  for (const raw of lines) {
    const line = (raw ?? '').trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split('\t');
    if (parts.length < 7) continue;
    const [domain, flag, path, secureStr, expiresStr, name, valueRaw] = parts;
    const secure = /^true$/i.test(secureStr) || secureStr === 'TRUE';
    const expires = Number(expiresStr) || 0;
    const value = (valueRaw ?? '').replace('\r', '');
    if (!domain || !name) continue;
    out.push({ domain, flag, path, secure, expires, name, value });
  }
  return out;
}
function domainMatches(cookieDomain, reqHost) {
  if (!cookieDomain) return false;
  const cd = cookieDomain.toLowerCase();
  const host = reqHost.toLowerCase();
  if (cd[0] === '.') {
    const bare = cd.slice(1);
    return host === bare || host.endsWith('.' + bare);
  }
  return host === cd;
}
function pathMatches(cookiePath, reqPath) {
  if (!cookiePath) return true;
  if (!reqPath) return true;
  return reqPath.startsWith(cookiePath);
}
class CookieJar {
  constructor() { this.store = new Map(); }
  loadFromNetscape(lines) {
    const rows = parseNetscapeLines(lines);
    for (const r of rows) {
      const domain = r.domain;
      const name = r.name;
      if (!this.store.has(domain)) this.store.set(domain, new Map());
      this.store.get(domain).set(name, {
        value: r.value, path: r.path || '/', secure: !!r.secure, expires: r.expires || 0
      });
    }
  }
  setCookiesFromResponse(resUrl, setCookieHeaders) {
    if (!setCookieHeaders) return;
    const u = new URL(resUrl);
    const host = u.hostname;
    const arr = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    for (const sc of arr) {
      const parts = sc.split(';').map(s => s.trim());
      const [nv, ...attrs] = parts;
      const eq = nv.indexOf('=');
      if (eq <= 0) continue;
      const name = nv.slice(0, eq);
      const value = nv.slice(1 + eq);
      let cPath = '/';
      let cDomain = host;
      let cSecure = false;
      let cExpires = 0;
      for (const a of attrs) {
        const [k, v] = a.split('=');
        const key = (k || '').toLowerCase();
        const val = v ? v.trim() : '';
        if (key === 'path' && val) cPath = val;
        else if (key === 'domain' && val) cDomain = val;
        else if (key === 'secure') cSecure = true;
        else if (key === 'expires' && val) {
          const t = Date.parse(val);
          if (!Number.isNaN(t)) cExpires = Math.floor(t / 1000);
        }
      }
      if (!this.store.has(cDomain)) this.store.set(cDomain, new Map());
      this.store.get(cDomain).set(name, { value, path: cPath, secure: cSecure, expires: cExpires });
    }
  }
  getCookieHeaderFor(urlStr) {
    const u = new URL(urlStr);
    const host = u.hostname;
    const path = u.pathname || '/';
    const isHttps = u.protocol === 'https:';
    const now = Math.floor(Date.now() / 1000);
    const pairs = [];
    for (const [domain, map] of this.store.entries()) {
      if (!domainMatches(domain, host)) continue;
      for (const [name, c] of map.entries()) {
        if (c.expires && c.expires < now) continue;
        if (!pathMatches(c.path, path)) continue;
        if (c.secure && !isHttps) continue;
        pairs.push(`${name}=${c.value}`);
      }
    }
    return pairs.join('; ');
  }
}

// ---------- OAuth + Xbox flow ----------
async function getTextSafe(resp) { try { return await resp.text(); } catch { return ''; } }

async function followRedirectsWithJar(jar, startUrl, maxHops = 20, wantBody = true, tag = 'follow', onHop = null) {
  let url = startUrl;
  let resp = await fetchSafe(jar, url, {}, `${tag}-GET`);
  let hops = 0;

  while (hops < maxHops) {
    const status = resp.status;
    const loc = resp.headers.get('location');
    if (loc && status >= 300 && status < 400) {
      let next = loc;
      if (/^\/\//.test(next)) next = 'https:' + next;
      if (!/^https?:\/\//i.test(next)) {
        const u = new URL(url);
        next = u.origin + next;
      }
      if (typeof onHop === 'function') {
        try { onHop(url, next, status, resp); } catch {}
      }
      url = next;
      resp = await fetchSafe(jar, url, {}, `${tag}-REDIR`);
      hops++;
      continue;
    }
    break;
  }
  const body = wantBody ? await getTextSafe(resp) : '';
  return { url, resp, body };
}

async function postForm(jar, baseUrl, formHtml, preferred = ['continue','yes','allow','accept','confirm']) {
  const formMatch = /<form[^>]*action="([^"]+)"[^>]*>([\s\S]*?)<\/form>/i.exec(formHtml);
  if (!formMatch) return null;
  let action = formMatch[1];
  const inner = formMatch[2] || '';
  if (/^\/\//.test(action)) action = 'https:' + action;
  if (!/^https?:\/\//i.test(action)) {
    const u0 = new URL(baseUrl);
    action = u0.origin + action;
  }

  const inputs = [...inner.matchAll(/<input[^>]+name="([^"]+)"[^>]*value="([^"]*)"/gi)]
    .map(x => ({ name: x[1], value: x[2] }));
  const buttons = [...inner.matchAll(/<button[^>]*name="([^"]+)"[^>]*value="([^"]*)"/gi)]
    .map(x => ({ name: x[1], value: x[2] }));

  let chosen = null;
  for (const p of preferred) {
    chosen = buttons.find(b => (b.name + '=' + b.value).toLowerCase().includes(p));
    if (chosen) break;
  }

  const params = new URLSearchParams();
  for (const { name, value } of inputs) params.append(name, value);
  if (chosen) params.append(chosen.name, chosen.value);
  if (!params.has('action')) params.set('action', 'continue');

  const resp = await fetchSafe(jar, action, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString()
  }, 'postForm');
  const loc = resp.headers.get('location') || action;
  return followRedirectsWithJar(jar, loc, 20, true, 'postForm-follow');
}

async function handleAr(jar, url) {
  const res = await fetchSafe(jar, url, { method: 'GET' }, 'ar-GET');
  const body = await getTextSafe(res);

  const forms = [];
  const formRe = /<form[^>]*action="([^"]+)"[^>]*>([\s\S]*?)<\/form>/gi;
  let m;
  while ((m = formRe.exec(body)) !== null) {
    const actionRaw = m[1];
    const html = m[2] || '';
    const hasPositive = /(Continue|Yes|Accept|Allow|Confirm)/i.test(html);
    const hasSubmit = /type="submit"/i.test(html);
    const inputs = [...html.matchAll(/<input[^>]+name="([^"]+)"[^>]*value="([^"]*)"/gi)].length;
    const score = (hasPositive ? 3 : 0) + (hasSubmit ? 2 : 0) + inputs / 10;
    forms.push({ actionRaw, html, score });
  }
  if (forms.length) {
    forms.sort((a, b) => b.score - a.score || b.html.length - a.html.length);
    const best = forms[0];
    return postForm(jar, url, `<form action="${best.actionRaw}">${best.html}</form>`);
  }

  const linkMatch = /<a[^>]+href="([^"]+)"[^>]*>(?:Continue|Yes|Accept|Allow|Confirm)<\/a>/i.exec(body);
  if (linkMatch) {
    let href = linkMatch[1];
    if (/^\/\//.test(href)) href = 'https:' + href;
    if (!/^https?:\/\//i.test(href)) {
      const u0 = new URL(url);
      href = u0.origin + href;
    }
    return followRedirectsWithJar(jar, href, 20, true, 'ar-link-follow');
  }

  try {
    const u = new URL(url);
    const ru = u.searchParams.get('ru');
    if (ru) {
      return followRedirectsWithJar(jar, ru, 20, true, 'ar-ru-follow');
    }
  } catch {}

  return { url, resp: res, body };
}

function extractCodeFromHop(prevUrl, nextUrl) {
  try {
    const u = new URL(nextUrl);
    if (u.hostname.toLowerCase().includes('sisu.xboxlive.com')
        && u.pathname.startsWith('/connect/oauth/XboxLive')) {
      const code = u.searchParams.get('code');
      if (code) return code;
    }
  } catch {}
  return null;
}

async function extractAccessTokenFromOAuth(netscapeLines) {
  const jar = new CookieJar();
  jar.loadFromNetscape(netscapeLines);

  let capturedCode = null;

  const initResp = await fetch(
    'https://sisu.xboxlive.com/connect/XboxLive/?state=login&cobrandId=8058f65d-ce06-4c30-9559-473c9275a65d&tid=896928775&ru=https%3A%2F%2Fwww.minecraft.net%2Fen-us%2Flogin&aid=1142970254',
    { headers: defaultHeaders(), redirect: 'manual' }
  );
  let startUrl = initResp.headers.get('location') || initResp.url;
  if (!startUrl) return { accessToken: null, capturedCode: null };

  const onHop = (prev, next) => {
    const maybeCode = extractCodeFromHop(prev, next);
    if (maybeCode && !capturedCode) {
      capturedCode = maybeCode;
      console.log('[auth-debug] captured sisu auth code (length):', String(capturedCode).length);
    }
  };

  let follow = await followRedirectsWithJar(jar, startUrl, 20, true, 'oauth-follow', onHop);
  let finalUrl = follow.url;
  let body = follow.body;

  if (!capturedCode && /^https:\/\/account\.live\.com\/ar\//i.test(finalUrl)) {
    const afterAr = await handleAr(jar, finalUrl);
    finalUrl = afterAr.url;
    body = afterAr.body || '';
  }

  if (!capturedCode && /login\.live\.com\/oauth20_authorize\.srf/i.test(finalUrl)) {
    const afterFm = await postForm(jar, finalUrl, body || '');
    if (afterFm) {
      finalUrl = afterFm.url;
      body = afterFm.body || body;
    }
  }

  if (finalUrl.includes('accessToken=')) {
    return { accessToken: finalUrl.split('accessToken=')[1], capturedCode };
  }
  let m =
    /"accessToken"\s*:\s*"([^"]+)"/i.exec(body) ||
    /accessToken=([A-Za-z0-9+/=._\-]+)/i.exec(body);
  if (m && m[1]) return { accessToken: m[1], capturedCode };

  return { accessToken: null, capturedCode };
}

// ---------- Xbox/MCS token exchange ----------
async function tryRpsUserAuthenticate(code, host, relyingParty, logTag) {
  const endpoint = `https://${host}/user/authenticate`;
  const payload = {
    RelyingParty: relyingParty,
    TokenType: 'JWT',
    Properties: { AuthMethod: 'RPS', SiteName: 'user.auth.xboxlive.com', RpsTicket: 'd=' + code }
  };
  const headers = { 'Accept': 'application/json', 'Content-Type': 'application/json', 'x-xbl-contract-version': '1' };
  const { res, status, text } = await postJsonWithRetry(endpoint, payload, headers, logTag, 3);
  let json = null;
  try { json = JSON.parse(text); } catch {}
  if (status < 200 || status >= 300) {
    console.log(`[auth-debug] ${logTag} HTTP ${status}`);
    const www = res.headers.get('www-authenticate');
    if (www) console.log(`[auth-debug] ${logTag} WWW-Authenticate:`, www);
    if (text) console.log(`[auth-debug] ${logTag} body:`, text.slice(0, 400));
    return null;
  }
  const userToken = json?.Token;
  const uhs = json?.DisplayClaims?.xui?.[0]?.uhs;
  if (!userToken || !uhs) {
    console.log(`[auth-debug] ${logTag} missing token/uhs:`, json);
    return null;
  }
  return { userToken, uhs };
}

async function xstsAuthorizeForMcs(userToken) {
  const payload = { RelyingParty: 'rp://api.minecraftservices.com/', TokenType: 'JWT', Properties: { SandboxId: 'RETAIL', UserTokens: [userToken] } };
  const headers = { 'Accept': 'application/json', 'Content-Type': 'application/json', 'x-xbl-contract-version': '1' };
  const { res, status, text } = await postJsonWithRetry('https://xsts.auth.xboxlive.com/xsts/authorize', payload, headers, 'xsts.authorize', 3);
  let json = null;
  try { json = JSON.parse(text); } catch {}
  if (status < 200 || status >= 300) {
    console.log('[auth-debug] xsts.authorize HTTP', status);
    const www = res.headers.get('www-authenticate');
    if (www) console.log('[auth-debug] xsts.authorize WWW-Authenticate:', www);
    if (text) console.log('[auth-debug] xsts.authorize body:', text.slice(0, 400));
    return null;
  }
  const xstsToken = json?.Token;
  const uhs = json?.DisplayClaims?.xui?.[0]?.uhs;
  if (!xstsToken || !uhs) {
    console.log('[auth-debug] xsts.authorize missing Token/UHS:', json);
    return null;
  }
  return { xstsToken, uhs };
}

// ---------- Cache writer ----------
function storeMinecraftToken(profileName, accessToken, username) {
  const baseDir = 'profiles';
  const profilePath = path.join(baseDir, profileName);
  if (!fs.existsSync(baseDir)) fs.mkdirSync(baseDir, { recursive: true });
  try { fsExtra.emptyDirSync(profilePath); } catch {}
  try { fs.rmdirSync(profilePath); } catch {}
  try { fs.mkdirSync(profilePath, { recursive: true }); } catch {}
  const tokenData = {
    mca: { username, roles: [], metadata: {}, access_token: accessToken, expires_in: 860400, token_type: 'Bearer', obtainedOn: Date.now() }
  };
  fs.writeFileSync(path.join(profilePath, 'e53407_mca-cache.json'), JSON.stringify(tokenData));
}

// ---------- Public API ----------
export function parseCookie(netscapeLines) {
  if (Array.isArray(netscapeLines)) return netscapeLines;
  if (typeof netscapeLines === 'string') return netscapeLines.split(/\r?\n/);
  return [];
}

async function getMinecraftToken(netscapeLines) {
  try {
    const { accessToken, capturedCode } = await extractAccessTokenFromOAuth(netscapeLines);
    if (accessToken) {
      try {
        const decoded = Buffer.from(accessToken.trim(), 'base64').toString('utf-8');
        const tokenData = JSON.parse(decoded);
        let uhs = null, xstsToken = null;
        for (const item of Object.values(tokenData)) {
          if (item.Item1 !== 'rp://api.minecraftservices.com/') continue;
          uhs = item.Item2?.DisplayClaims?.xui?.[0]?.uhs;
          xstsToken = item.Item2?.Token;
          if (uhs && xstsToken) break;
        }
        if (uhs && xstsToken) {
          const headers = defaultHeaders({ 'Accept': '*/*', 'Content-Type': 'application/json', 'Referer': 'https://www.minecraft.net/', 'Origin': 'https://www.minecraft.net' });
          const { text } = await postJsonWithRetry('https://api.minecraftservices.com/authentication/login_with_xbox', { identityToken: 'XBL 3.0 x=' + uhs + ';' + xstsToken, ensureLegacyEnabled: true }, headers, 'login_with_xbox-legacy', 3);
          let parsed;
          try { parsed = JSON.parse(text); } catch { console.log('[auth-debug] Non-JSON login_with_xbox response:', text.slice(0, 400)); return null; }
          const username = parsed.username;
          const accessTokenMc = parsed.access_token;
          if (!accessTokenMc) { console.log('[auth-debug] No access_token in login_with_xbox response:', parsed); return null; }
          return { uuid: username, accessToken: accessTokenMc };
        }
      } catch {}
    }
    if (!capturedCode) {
      console.log('[auth-debug] No accessToken and no capturedCode; cannot continue');
      return null;
    }

    let ua = await tryRpsUserAuthenticate(capturedCode, 'user.auth.xboxlive.com', 'http://auth.xboxlive.com', 'user.auth (auth.xboxlive.com)')
      .catch(e => { console.log('[auth-debug] user.auth fetch error:', e?.message || String(e)); return null; });
    if (!ua) {
      ua = await tryRpsUserAuthenticate(capturedCode, 'user.auth.xboxlive.com', 'http://xboxlive.com', 'user.auth (xboxlive.com)')
        .catch(e => { console.log('[auth-debug] user.auth alt fetch error:', e?.message || String(e)); return null; });
    }
    if (!ua) {
      ua = await tryRpsUserAuthenticate(capturedCode, 'xbl.auth.xboxlive.com', 'http://xboxlive.com', 'xbl.auth fallback')
        .catch(e => { console.log('[auth-debug] xbl.auth fallback fetch error:', e?.message || String(e)); return null; });
    }
    if (!ua) { console.log('[auth-debug] All RPS variants failed'); return null; }

    const xsts = await xstsAuthorizeForMcs(ua.userToken).catch(e => { console.log('[auth-debug] xsts.authorize fetch error:', e?.message || String(e)); return null; });
    if (!xsts) { console.log('[auth-debug] xstsAuthorizeForMcs failed'); return null; }

    const identityToken = 'XBL 3.0 x=' + xsts.uhs + ';' + xsts.xstsToken;
    const headers = defaultHeaders({ 'Accept': '*/*', 'Content-Type': 'application/json', 'Referer': 'https://www.minecraft.net/', 'Origin': 'https://www.minecraft.net' });
    const { text } = await postJsonWithRetry('https://api.minecraftservices.com/authentication/login_with_xbox', { identityToken, ensureLegacyEnabled: true }, headers, 'login_with_xbox', 3);
    let parsed;
    try { parsed = JSON.parse(text); } catch { console.log('[auth-debug] Non-JSON login_with_xbox response:', text.slice(0, 400)); return null; }
    const username = parsed.username;
    const accessTokenMc = parsed.access_token;
    if (!accessTokenMc) { console.log('[auth-debug] No access_token in login_with_xbox response:', parsed); return null; }
    return { uuid: username, accessToken: accessTokenMc };

  } catch (e) {
    console.log('Error in getMinecraftToken:', e.message);
    return null;
  }
}

export async function getUsername(netscapeLines, proxyLineRaw) {
  try {
    if (proxyLineRaw) {
      // Important: if a raw host:port:user:pass is passed here, we’ll try SOCKS first; if it fails,
      // we fall back to HTTP CONNECT automatically (as your code already does).
      // If you want to force HTTP CONNECT from the caller, call setAuthProxyHttpUrl(httpUrl) directly.
      setProxyFromLine(proxyLineRaw);
    }
    const tokenData = await getMinecraftToken(netscapeLines);
    if (tokenData === null) return null;

    const { uuid, accessToken } = tokenData;
    const headers = defaultHeaders({ 'Accept': '*/*', 'Authorization': 'Bearer ' + accessToken, 'Referer': 'https://www.minecraft.net/', 'Origin': 'https://www.minecraft.net' });
    const response = await fetch('https://api.minecraftservices.com/minecraft/profile', { headers, redirect: 'manual' });
    const profileData = await response.text();
    let profileJson;
    try { profileJson = JSON.parse(profileData); } catch { console.log('[auth-debug] Non-JSON minecraft/profile response:', profileData.slice(0, 400)); return null; }
    if (profileJson && profileJson.name) {
      storeMinecraftToken(profileJson.name, accessToken, uuid);
      return profileJson.name;
    } else {
      console.log('Failed to get username: ' + JSON.stringify(profileJson), 'error');
      return null;
    }
  } catch (error) {
    console.log('Error in getUsername: ' + error.message, 'error');
    return null;
  }
}