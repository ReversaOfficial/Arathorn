/**
 * TERRAS DE ARATHORN — Backend Server v2
 * Node.js puro (sem dependencias externas)
 * Banco de dados: arquivo JSON local
 * Novidades: PvP Duelos, Guerras de Cla, Jogadores Online (SSE)
 */

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const PORT    = 3000;
const DB_FILE = path.join(__dirname, 'db.json');
const SECRET  = 'arathorn_secret_key_2024_change_in_production';

// ONLINE TRACKING
const onlineMap  = new Map(); // username -> { lastSeen, name, race, level, power, clanName }
const sseClients = new Map(); // username -> res

function markOnline(username, info) {
  onlineMap.set(username, Object.assign({}, info, { lastSeen: Date.now() }));
}
function getOnlinePlayers() {
  const cutoff = Date.now() - 90000;
  for (const [u, d] of onlineMap) { if (d.lastSeen < cutoff) onlineMap.delete(u); }
  return Array.from(onlineMap.entries()).map(([username, d]) => Object.assign({ username }, d));
}
function broadcastSSE(event, data) {
  const msg = 'event: ' + event + '\ndata: ' + JSON.stringify(data) + '\n\n';
  for (const [, r] of sseClients) { try { r.write(msg); } catch(e) {} }
}
function sendSSE(username, event, data) {
  const r = sseClients.get(username);
  if (!r) return;
  try { r.write('event: ' + event + '\ndata: ' + JSON.stringify(data) + '\n\n'); } catch(e) {}
}
function broadcastTrade(trade, event) {
  sendSSE(trade.sideA.username, event, { trade });
  sendSSE(trade.sideB.username, event, { trade });
}

// DATABASE
function loadDB() {
  try { if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch(e) {}
  return { users: {}, duels: [], clanWars: [] };
}
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }

// CRYPTO
function hashPassword(p) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.createHmac('sha256', salt).update(p).digest('hex');
}
function verifyPassword(p, stored) {
  const [salt, hash] = stored.split(':');
  return crypto.createHmac('sha256', salt).update(p).digest('hex') === hash;
}
function makeToken(u) {
  const payload = Buffer.from(JSON.stringify({ username: u, ts: Date.now() })).toString('base64');
  return payload + '.' + crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
}
function verifyToken(token) {
  if (!token) return null;
  const idx = token.lastIndexOf('.');
  if (idx < 0) return null;
  const payload = token.slice(0, idx);
  const sig     = token.slice(idx + 1);
  if (crypto.createHmac('sha256', SECRET).update(payload).digest('hex') !== sig) return null;
  try {
    const d = JSON.parse(Buffer.from(payload, 'base64').toString());
    if (Date.now() - d.ts > 30 * 86400000) return null;
    return d.username;
  } catch(e) { return null; }
}

// HTTP HELPERS
function readBody(req) {
  return new Promise((res, rej) => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > 5e6) rej(new Error('big')); });
    req.on('end', () => { try { res(JSON.parse(d)); } catch(e) { res({}); } });
    req.on('error', rej);
  });
}
function send(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(json),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  });
  res.end(json);
}

// ── RATE LIMITING ───────────────────────────────────────────────────────────
const rateLimits = new Map(); // ip -> { count, windowStart }
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX    = 120;   // 120 requests per minute per IP
const AUTH_RATE_LIMIT_MAX = 10;  // 10 auth attempts per minute per IP

function getClientIP(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function checkRateLimit(req, isAuth) {
  const ip = getClientIP(req);
  const limit = isAuth ? AUTH_RATE_LIMIT_MAX : RATE_LIMIT_MAX;
  const key = (isAuth ? 'auth:' : 'gen:') + ip;
  const now = Date.now();
  let entry = rateLimits.get(key);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW) {
    entry = { count: 1, windowStart: now };
    rateLimits.set(key, entry);
    return true;
  }
  entry.count++;
  if (entry.count > limit) return false;
  return true;
}

// Clean up old rate limit entries every 5 minutes
setInterval(() => {
  const cutoff = Date.now() - RATE_LIMIT_WINDOW * 2;
  for (const [k, v] of rateLimits) {
    if (v.windowStart < cutoff) rateLimits.delete(k);
  }
}, 5 * 60000);

// ── INPUT VALIDATION HELPERS ────────────────────────────────────────────────
function safeNumber(val, min, max) {
  const n = Number(val);
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, Math.floor(n)));
}
function safeString(val, maxLen) {
  if (typeof val !== 'string') return '';
  return val.slice(0, maxLen || 200);
}
function isValidUsername(u) {
  return typeof u === 'string' && /^[a-z0-9_]{3,24}$/.test(u);
}


// ═══════════════════════════════════════════════════════════════════════════
// AUTOMATIC BACKUP SYSTEM
// ═══════════════════════════════════════════════════════════════════════════
// - Daily backup at midnight (server time)
// - Backups go to ./backups/ folder with timestamped filenames
// - Keeps last 30 daily backups + last 7 hourly emergency backups
// - Also creates an immediate backup on server startup if 24h+ since last one
// ═══════════════════════════════════════════════════════════════════════════

const BACKUP_DIR = path.join(__dirname, 'backups');
const MAX_DAILY_BACKUPS  = 30;  // keep 30 days
const MAX_HOURLY_BACKUPS = 7;   // keep 7 emergency hourly backups

function ensureBackupDir() {
  try {
    if (!fs.existsSync(BACKUP_DIR)) {
      fs.mkdirSync(BACKUP_DIR, { recursive: true });
      console.log('[BACKUP] Pasta criada: ' + BACKUP_DIR);
    }
  } catch(e) {
    console.error('[BACKUP] Erro ao criar pasta:', e.message);
  }
}

function formatBackupTimestamp(date) {
  // ex: 2026-05-03_00-00-00
  const pad = n => String(n).padStart(2, '0');
  return date.getFullYear() + '-' + pad(date.getMonth()+1) + '-' + pad(date.getDate())
    + '_' + pad(date.getHours()) + '-' + pad(date.getMinutes()) + '-' + pad(date.getSeconds());
}

function makeBackup(prefix) {
  prefix = prefix || 'daily';
  ensureBackupDir();
  if (!fs.existsSync(DB_FILE)) {
    console.warn('[BACKUP] db.json nao existe ainda — pulando backup.');
    return null;
  }
  const timestamp = formatBackupTimestamp(new Date());
  const filename = 'db_' + prefix + '_' + timestamp + '.json';
  const dest = path.join(BACKUP_DIR, filename);
  try {
    fs.copyFileSync(DB_FILE, dest);
    const size = fs.statSync(dest).size;
    const sizeKB = (size / 1024).toFixed(1);
    console.log('[BACKUP] Criado: ' + filename + ' (' + sizeKB + ' KB)');
    cleanOldBackups(prefix);
    return dest;
  } catch(e) {
    console.error('[BACKUP] Erro ao criar backup:', e.message);
    return null;
  }
}

function cleanOldBackups(prefix) {
  try {
    const files = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith('db_' + prefix + '_') && f.endsWith('.json'))
      .map(f => ({ name: f, time: fs.statSync(path.join(BACKUP_DIR, f)).mtimeMs }))
      .sort((a, b) => b.time - a.time); // newest first

    const maxKeep = prefix === 'hourly' ? MAX_HOURLY_BACKUPS : MAX_DAILY_BACKUPS;
    const toDelete = files.slice(maxKeep);
    toDelete.forEach(f => {
      try {
        fs.unlinkSync(path.join(BACKUP_DIR, f.name));
        console.log('[BACKUP] Removido (rotacao): ' + f.name);
      } catch(e) {}
    });
  } catch(e) {
    console.error('[BACKUP] Erro na limpeza:', e.message);
  }
}

// Schedule next midnight backup
function scheduleMidnightBackup() {
  const now = new Date();
  const nextMidnight = new Date(now);
  nextMidnight.setDate(now.getDate() + 1);
  nextMidnight.setHours(0, 0, 0, 0);
  const msUntilMidnight = nextMidnight - now;
  console.log('[BACKUP] Proximo backup automatico em ' + Math.round(msUntilMidnight/3600000) + 'h ' + (new Date(nextMidnight)).toLocaleString('pt-BR'));
  setTimeout(() => {
    makeBackup('daily');
    // Schedule next one (recursive, every 24h)
    setInterval(() => makeBackup('daily'), 24 * 60 * 60 * 1000);
  }, msUntilMidnight);
}

// Hourly emergency backup (rotates faster, keeps only 7)
function scheduleHourlyBackup() {
  setInterval(() => makeBackup('hourly'), 60 * 60 * 1000);
}

// On startup: if last backup is > 24h old (or none exist), make one immediately
function startupBackupCheck() {
  ensureBackupDir();
  try {
    const files = fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith('db_daily_') && f.endsWith('.json'));
    if (files.length === 0) {
      console.log('[BACKUP] Nenhum backup encontrado — criando inicial...');
      makeBackup('daily');
      return;
    }
    // Find newest
    const newest = files
      .map(f => ({ name: f, time: fs.statSync(path.join(BACKUP_DIR, f)).mtimeMs }))
      .sort((a, b) => b.time - a.time)[0];
    const ageHours = (Date.now() - newest.time) / 3600000;
    if (ageHours > 24) {
      console.log('[BACKUP] Ultimo backup tem ' + Math.round(ageHours) + 'h — criando novo...');
      makeBackup('daily');
    } else {
      console.log('[BACKUP] Ultimo backup tem ' + Math.round(ageHours) + 'h (recente).');
    }
  } catch(e) {
    console.error('[BACKUP] Erro no check inicial:', e.message);
  }
}

// Manual backup endpoint (for emergencies)
function makeManualBackup() {
  return makeBackup('manual');
}

function sendFile(res, fp, ct) {
  try { const d = fs.readFileSync(fp); res.writeHead(200, { 'Content-Type': ct }); res.end(d); }
  catch(e) { res.writeHead(404); res.end('Not found'); }
}
function getToken(req) {
  const a = req.headers['authorization'] || '';
  return a.startsWith('Bearer ') ? a.slice(7) : null;
}

// POWER CALCULATION
function calcPower(g) {
  if (!g) return 0;
  return Math.round((g.level||1)*100 + ((g.stats&&g.stats.kills)||0)*2 + (g.str||10)*8 + (g.res||10)*6 + (g.mag||8)*4);
}


// ─── SELL PRICE CALCULATOR ──────────────────────────────────────────────────
function calcSellPrice(invId) {
  if (!invId) return 1;
  const clean = invId.replace('!lucky','');
  const baseId = clean.split('+')[0];
  const refine = parseInt((clean.split('+')[1])||'0') || 0;
  // Find item price from SHOP_ITEMS catalog
  const TIER_BASE_PRICES = {
    1:80, 2:200, 3:500, 4:1200, 5:50000, 6:150000, 7:500000, 8:2000000
  };
  const GRADE_MULT = { normal:0.15, excellent:0.18, superrare:0.20, epic:0.22, supreme:0.25 };
  // Estimate: use tier if available, else guess from id prefix
  const tierMatch = invId.match(/[a-z]+w([1-8])/);
  const tier = tierMatch ? parseInt(tierMatch[1]) : 1;
  const basePrice = TIER_BASE_PRICES[tier] || 100;
  const gradeMult = GRADE_MULT['normal']; // default, we dont have full catalog on server
  let price = Math.round(basePrice * gradeMult);
  // Refine bonus: +10% per refine level
  if (refine > 0) price = Math.round(price * (1 + refine * 0.10));
  // Lucky bonus: +20%
  if (invId.includes('!lucky')) price = Math.round(price * 1.20);
  return Math.max(1, price);
}

// ROUTES
async function handleRequest(req, res) {
  const url = req.url.split('?')[0];
  const method = req.method;

  if (method === 'OPTIONS') { send(res, 200, {}); return; }
  if (method === 'GET' && url === '/') { sendFile(res, path.join(__dirname, 'game.html'), 'text/html; charset=utf-8'); return; }

  // ── Rate limiting (skip SSE because it's a long-lived connection) ──
  const isAuthRoute = url === '/api/login' || url === '/api/register';
  if (url.startsWith('/api/') && url !== '/api/events') {
    if (!checkRateLimit(req, isAuthRoute)) {
      send(res, 429, { error: 'Muitas requisicoes. Tente novamente em alguns segundos.' });
      return;
    }
  }

  // SSE stream
  if (method === 'GET' && url === '/api/events') {
    const username = verifyToken(getToken(req));
    if (!username) { res.writeHead(401); res.end(); return; }
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'Access-Control-Allow-Origin': '*' });
    res.write('event: connected\ndata: {}\n\n');
    sseClients.set(username, res);
    res.write('event: online\ndata: ' + JSON.stringify(getOnlinePlayers()) + '\n\n');
    req.on('close', () => { sseClients.delete(username); onlineMap.delete(username); broadcastSSE('online', getOnlinePlayers()); });
    return;
  }

  // Heartbeat
  if (method === 'POST' && url === '/api/heartbeat') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { info } = await readBody(req);
    markOnline(username, info || {});
    broadcastSSE('online', getOnlinePlayers());
    send(res, 200, { ok: true });
    return;
  }

  // Online list
  if (method === 'GET' && url === '/api/online') {
    send(res, 200, { players: getOnlinePlayers() });
    return;
  }

  // Register
  if (method === 'POST' && url === '/api/register') {
    const body = await readBody(req);
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    if (!username || !password) { send(res, 400, { error: 'Usuario e senha obrigatorios.' }); return; }
    if (username.length < 3 || username.length > 24) { send(res, 400, { error: 'Usuario: 3-24 caracteres.' }); return; }
    if (password.length < 6 || password.length > 200) { send(res, 400, { error: 'Senha: 6-200 caracteres.' }); return; }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) { send(res, 400, { error: 'Usuario: apenas letras, numeros e _' }); return; }
    // Block reserved names
    const reserved = ['admin','root','system','server','null','undefined','anonymous','moderator','mod','staff','support'];
    if (reserved.includes(username.toLowerCase())) { send(res, 400, { error: 'Nome reservado.' }); return; }
    const db = loadDB();
    const key = username.toLowerCase();
    if (db.users[key]) { send(res, 409, { error: 'Nome de usuario ja existe.' }); return; }
    db.users[key] = { username, password: hashPassword(password), createdAt: Date.now(), lastLogin: Date.now(), gameState: null };
    saveDB(db);
    send(res, 201, { token: makeToken(key), username });
    return;
  }

  // Login
  if (method === 'POST' && url === '/api/login') {
    const body = await readBody(req);
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    if (!username || !password) { send(res, 400, { error: 'Usuario e senha obrigatorios.' }); return; }
    if (username.length > 24 || password.length > 200) { send(res, 400, { error: 'Credenciais invalidas.' }); return; }
    const db = loadDB();
    const key = username.toLowerCase();
    const user = db.users[key];
    // Always run hash to prevent timing attacks (even if user doesnt exist)
    const dummyHash = 'a'.repeat(32) + ':' + 'b'.repeat(64);
    const hashToCheck = user ? user.password : dummyHash;
    const passwordOk = verifyPassword(password, hashToCheck);
    if (!user || !passwordOk) {
      send(res, 401, { error: 'Usuario ou senha incorretos.' });
      return;
    }
    user.lastLogin = Date.now();
    saveDB(db);
    send(res, 200, { token: makeToken(key), username: user.username, hasCharacter: !!user.gameState });
    return;
  }

  // Save — ANTI-CHEAT: validate against existing state to prevent tampering
  if (method === 'POST' && url === '/api/save') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { gameState } = await readBody(req);
    if (!gameState || typeof gameState !== 'object') { send(res, 400, { error: 'gameState invalido.' }); return; }
    const db = loadDB();
    if (!db.users[username]) { send(res, 404, { error: 'Usuario nao encontrado.' }); return; }

    const existing = db.users[username].gameState;
    if (existing) {
      // ── ANTI-CHEAT VALIDATION ──────────────────────────────────────────
      // Prevent obvious tampering: gold, level, stats can never DECREASE drastically
      // unless the server explicitly approved it (via mission/duel/etc routes).

      // Cap level changes — client cannot self-promote
      const oldLevel = existing.level || 1;
      const newLevel = safeNumber(gameState.level, 1, 999);
      if (newLevel - oldLevel > 5) {
        // Suspicious — allow only +5 levels per save (covers natural level-ups)
        gameState.level = oldLevel;
      } else {
        gameState.level = newLevel;
      }

      // Cap individual stats — anti gold/stat injection
      gameState.gold = safeNumber(gameState.gold, 0, 999999999999);
      gameState.str  = safeNumber(gameState.str,  1, 99999);
      gameState.dex  = safeNumber(gameState.dex,  1, 99999);
      gameState.mag  = safeNumber(gameState.mag,  1, 99999);
      gameState.res  = safeNumber(gameState.res,  1, 99999);
      gameState.hp   = safeNumber(gameState.hp,   0, 999999);
      gameState.mana = safeNumber(gameState.mana, 0, 999999);
      gameState.stam = safeNumber(gameState.stam, 0, 999);
      gameState.hpMax   = safeNumber(gameState.hpMax,   1, 999999);
      gameState.manaMax = safeNumber(gameState.manaMax, 1, 999999);
      gameState.stamMax = safeNumber(gameState.stamMax, 1, 999);
      gameState.xp      = safeNumber(gameState.xp, 0, Number.MAX_SAFE_INTEGER);

      // Suspicious gold jump: client cant gain >10M gold per save unless legit (raids)
      const oldGold = existing.gold || 0;
      if (gameState.gold - oldGold > 10000000) {
        // Flag for monitoring — keep old value
        gameState.gold = oldGold;
        console.warn('[ANTI-CHEAT] Suspicious gold jump for ' + username + ': ' + oldGold + ' -> ' + gameState.gold);
      }

      // Cap stats jumps too (per save) — prevents instant max stats
      ['str','dex','mag','res'].forEach(s => {
        const oldS = existing[s] || 1;
        if (gameState[s] - oldS > 50) {
          gameState[s] = oldS;
          console.warn('[ANTI-CHEAT] Suspicious '+s+' jump for ' + username);
        }
      });

      // String fields — sanitize to prevent XSS
      if (typeof gameState.name === 'string')     gameState.name = safeString(gameState.name, 28);
      if (typeof gameState.clanName === 'string') gameState.clanName = safeString(gameState.clanName, 30);
      if (typeof gameState.clanTag === 'string')  gameState.clanTag = safeString(gameState.clanTag, 5);

      // Inventory size cap (prevent DoS via unbounded array)
      if (Array.isArray(gameState.inventory) && gameState.inventory.length > 500) {
        gameState.inventory = gameState.inventory.slice(0, 500);
      }
      if (Array.isArray(gameState.consumables) && gameState.consumables.length > 200) {
        gameState.consumables = gameState.consumables.slice(0, 200);
      }
      if (Array.isArray(gameState.log) && gameState.log.length > 100) {
        gameState.log = gameState.log.slice(0, 100);
      }
    } else {
      // First save (character creation) — basic validation only
      gameState.level = 1;
      gameState.gold  = safeNumber(gameState.gold, 0, 1000); // starting gold cap
      gameState.xp    = 0;
      if (typeof gameState.name === 'string') gameState.name = safeString(gameState.name, 28);
      else { send(res, 400, { error: 'Nome invalido.' }); return; }
      // Block clan privileges on creation
      gameState.clanName = null;
      gameState.clanTag  = null;
      gameState.clanRole = 'member';
    }

    db.users[username].gameState = gameState;
    db.users[username].savedAt = Date.now();
    saveDB(db);
    send(res, 200, { ok: true, savedAt: Date.now() });
    return;
  }

  // Load
  if (method === 'GET' && url === '/api/load') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const db = loadDB();
    const user = db.users[username];
    if (!user) { send(res, 404, { error: 'Usuario nao encontrado.' }); return; }
    send(res, 200, { gameState: user.gameState || null, username: user.username });
    return;
  }

  // Leaderboard
  if (method === 'GET' && url === '/api/leaderboard') {
    const db = loadDB();
    const all = Object.values(db.users).filter(u => u.gameState).map(u => {
      const g = u.gameState;
      return {
        name: g.name||u.username, username: u.username, race: g.race||'humano',
        level: g.level||1, kills: (g.stats&&g.stats.kills)||0,
        missions: (g.stats&&g.stats.missions)||0,
        pvpWins: (g.stats&&g.stats.pvpWins)||0,
        warWins: (g.stats&&g.stats.warWins)||0,
        power: calcPower(g), clanName: g.clanName||null,
        profilePrivate: g.profilePrivate||false,
      };
    });
    send(res, 200, { leaderboard: all.sort((a,b)=>b.power-a.power).slice(0,100) });
    return;
  }

  // Clans
  if (method === 'GET' && url === '/api/clans') {
    const db = loadDB();
    const cm = {};
    Object.values(db.users).forEach(u => {
      if (!u.gameState || !u.gameState.clanName) return;
      const g = u.gameState; const cn = g.clanName;
      if (!cm[cn]) cm[cn] = { name:cn, tag:g.clanTag||'---', members:0, power:0, wins:0 };
      cm[cn].members++; cm[cn].power += calcPower(g); cm[cn].wins += g.clanWins||0;
    });
    send(res, 200, { clans: Object.values(cm).sort((a,b)=>b.power-a.power).slice(0,20) });
    return;
  }

  // ═══════════════════════════════════════
  // PVP DUELOS
  // ═══════════════════════════════════════

  // Desafiar
  if (method === 'POST' && url === '/api/duel/challenge') {
    const challenger = verifyToken(getToken(req));
    if (!challenger) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { targetUsername } = await readBody(req);
    if (!targetUsername) { send(res, 400, { error: 'Alvo necessario.' }); return; }
    const db = loadDB();
    const cu = db.users[challenger];
    const tu = db.users[targetUsername.toLowerCase()];
    if (!tu || !tu.gameState) { send(res, 404, { error: 'Jogador nao encontrado.' }); return; }
    if (targetUsername.toLowerCase() === challenger) { send(res, 400, { error: 'Nao pode se desafiar.' }); return; }
    if (!cu.gameState) { send(res, 400, { error: 'Crie um personagem primeiro.' }); return; }
    if (!db.duels) db.duels = [];
    const ex = db.duels.find(d => d.status==='pending' && ((d.challenger===challenger&&d.target===targetUsername.toLowerCase())||(d.challenger===targetUsername.toLowerCase()&&d.target===challenger)));
    if (ex) { send(res, 409, { error: 'Ja existe um duelo pendente entre voces.' }); return; }
    const duel = {
      id: crypto.randomBytes(8).toString('hex'),
      challenger, challengerName: cu.gameState.name, challengerPower: calcPower(cu.gameState),
      target: targetUsername.toLowerCase(), targetName: tu.gameState.name, targetPower: calcPower(tu.gameState),
      status: 'pending', createdAt: Date.now(), expiresAt: Date.now() + 300000,
    };
    db.duels.push(duel);
    if (db.duels.length > 300) db.duels = db.duels.slice(-300);
    saveDB(db);
    broadcastSSE('duel_challenge', { duel });
    send(res, 200, { ok: true, duel });
    return;
  }

  // Responder duelo
  if (method === 'POST' && url === '/api/duel/respond') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { duelId, accept } = await readBody(req);
    const db = loadDB();
    if (!db.duels) db.duels = [];
    const duel = db.duels.find(d => d.id === duelId);
    if (!duel) { send(res, 404, { error: 'Duelo nao encontrado.' }); return; }
    if (duel.target !== username) { send(res, 403, { error: 'Este duelo nao e para voce.' }); return; }
    if (duel.status !== 'pending') { send(res, 400, { error: 'Duelo ja foi resolvido.' }); return; }
    if (Date.now() > duel.expiresAt) { duel.status = 'expired'; saveDB(db); send(res, 400, { error: 'Duelo expirado.' }); return; }
    if (!accept) {
      duel.status = 'declined'; saveDB(db);
      broadcastSSE('duel_update', { duel });
      send(res, 200, { ok: true, result: 'declined' });
      return;
    }
    // Resolver duelo
    const cu = db.users[duel.challenger];
    const tu = db.users[duel.target];
    const cg = cu.gameState; const tg = tu.gameState;
    const cP = calcPower(cg); const tP = calcPower(tg);
    const cWins = cP*(0.92+Math.random()*0.16) >= tP*(0.92+Math.random()*0.16);
    const [wUser, lUser, wg, lg] = cWins ? [cu, tu, cg, tg] : [tu, cu, tg, cg];
    const goldStolen = Math.max(1, Math.round((lg.gold||0)*0.10));
    lg.gold = Math.max(0, (lg.gold||0) - goldStolen);
    wg.gold = (wg.gold||0) + goldStolen;
    if (!wg.stats) wg.stats = {}; wg.stats.pvpWins = (wg.stats.pvpWins||0)+1;
    if (!lg.stats) lg.stats = {}; lg.stats.pvpLosses = (lg.stats.pvpLosses||0)+1;
    if (!wg.log) wg.log = []; wg.log.unshift({ msg: '⚔ PvP: Venceu duelo contra '+lg.name+'! +'+goldStolen+' ouro', cls:'good' });
    if (!lg.log) lg.log = []; lg.log.unshift({ msg: '⚔ PvP: Perdeu duelo contra '+wg.name+'. -'+goldStolen+' ouro', cls:'bad' });
    cu.gameState = cg; tu.gameState = tg;
    duel.status = 'done';
    duel.winner = cWins ? duel.challenger : duel.target;
    duel.loser  = cWins ? duel.target : duel.challenger;
    duel.winnerName = wg.name; duel.loserName = lg.name;
    duel.winnerPower = cWins ? cP : tP; duel.loserPower = cWins ? tP : cP;
    duel.goldStolen = goldStolen; duel.resolvedAt = Date.now();
    saveDB(db);
    broadcastSSE('duel_update', { duel });
    send(res, 200, { ok: true, duel });
    return;
  }

  // Meus duelos
  if (method === 'GET' && url === '/api/duel/list') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const db = loadDB();
    if (!db.duels) db.duels = [];
    db.duels.forEach(d => { if (d.status==='pending' && Date.now()>d.expiresAt) d.status='expired'; });
    const myDuels = db.duels.filter(d => d.challenger===username||d.target===username).sort((a,b)=>b.createdAt-a.createdAt).slice(0,30);
    send(res, 200, { duels: myDuels });
    return;
  }

  // Historico publico de duelos
  if (method === 'GET' && url === '/api/duel/history') {
    const db = loadDB();
    if (!db.duels) { send(res, 200, { duels: [] }); return; }
    send(res, 200, { duels: db.duels.filter(d=>d.status==='done').sort((a,b)=>b.resolvedAt-a.resolvedAt).slice(0,20) });
    return;
  }

  // ═══════════════════════════════════════
  // GUERRAS DE CLA
  // ═══════════════════════════════════════

  // Declarar guerra
  if (method === 'POST' && url === '/api/clanwar/declare') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { targetClan } = await readBody(req);
    const db = loadDB();
    const user = db.users[username];
    if (!user||!user.gameState) { send(res, 400, { error: 'Personagem nao encontrado.' }); return; }
    const myClan = user.gameState.clanName;
    if (!myClan) { send(res, 400, { error: 'Voce nao possui um cla.' }); return; }
    if (user.gameState.clanRole !== 'leader') { send(res, 403, { error: 'Apenas o lider pode declarar guerras.' }); return; }
    if (!targetClan || targetClan === myClan) { send(res, 400, { error: 'Cla alvo invalido.' }); return; }
    if (!db.clanWars) db.clanWars = [];

    const allUsers = Object.values(db.users).filter(u => u.gameState);
    const c1m = allUsers.filter(u => u.gameState.clanName===myClan);
    const c2m = allUsers.filter(u => u.gameState.clanName===targetClan);
    if (!c2m.length) { send(res, 404, { error: 'Cla alvo nao encontrado.' }); return; }

    const c1p = c1m.reduce((s,u)=>s+calcPower(u.gameState),0);
    const c2p = c2m.reduce((s,u)=>s+calcPower(u.gameState),0);
    const c1Wins = c1p*(0.92+Math.random()*0.16) >= c2p*(0.92+Math.random()*0.16);
    const [winM, loseM, winClan, loseClan] = c1Wins ? [c1m,c2m,myClan,targetClan] : [c2m,c1m,targetClan,myClan];

    let totalSpoils = 0;
    loseM.forEach(u => {
      const g = u.gameState;
      const lost = Math.max(0, Math.round((g.gold||0)*0.20));
      g.gold = Math.max(0,(g.gold||0)-lost); totalSpoils += lost;
      if (!g.stats) g.stats = {}; g.stats.warLosses=(g.stats.warLosses||0)+1;
      if (!g.log) g.log = [];
      g.log.unshift({ msg:'🏴 Guerra: '+loseClan+' foi derrotado por '+winClan+'. -'+lost+' ouro saqueado.', cls:'bad' });
      db.users[u.username].gameState = g;
    });
    winM.forEach(u => {
      const g = u.gameState;
      if (!g.stats) g.stats = {}; g.stats.warWins=(g.stats.warWins||0)+1;
      if (!g.log) g.log = [];
      g.log.unshift({ msg:'🏆 Guerra: '+winClan+' venceu '+loseClan+'! Espolios: '+totalSpoils+' ouro no tesouro.', cls:'good' });
      if (g.clanRole==='leader') { g.clanGold=(g.clanGold||0)+totalSpoils; g.clanWins=(g.clanWins||0)+1; }
      db.users[u.username].gameState = g;
    });

    const war = {
      id: crypto.randomBytes(8).toString('hex'),
      clan1: myClan, clan1Tag: user.gameState.clanTag||'---', clan1Power: c1p,
      clan1Members: c1m.map(u=>({ username:u.username, name:u.gameState.name, power:calcPower(u.gameState) })),
      clan2: targetClan, clan2Tag: c2m[0].gameState.clanTag||'---', clan2Power: c2p,
      clan2Members: c2m.map(u=>({ username:u.username, name:u.gameState.name, power:calcPower(u.gameState) })),
      status:'done', winner:winClan, loser:loseClan, totalSpoils,
      declaredBy: username, declaredAt:Date.now(), resolvedAt:Date.now(),
    };
    db.clanWars.push(war);
    if (db.clanWars.length>100) db.clanWars=db.clanWars.slice(-100);
    saveDB(db);
    broadcastSSE('clan_war', { war });
    send(res, 200, { ok:true, war });
    return;
  }

  // Historico de guerras
  if (method === 'GET' && url === '/api/clanwar/history') {
    const db = loadDB();
    if (!db.clanWars) { send(res, 200, { wars: [] }); return; }
    send(res, 200, { wars: db.clanWars.filter(w=>w.status==='done').sort((a,b)=>b.resolvedAt-a.resolvedAt).slice(0,30) });
    return;
  }

  // Distribuir espolios
  if (method === 'POST' && url === '/api/clanwar/distribute') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { distributions } = await readBody(req);
    if (!distributions||!Array.isArray(distributions)) { send(res, 400, { error: 'Distribuicoes necessarias.' }); return; }
    const db = loadDB();
    const lu = db.users[username];
    if (!lu||!lu.gameState) { send(res, 400, { error: 'Personagem nao encontrado.' }); return; }
    if (lu.gameState.clanRole!=='leader') { send(res, 403, { error: 'Apenas o lider pode distribuir.' }); return; }
    const avail = lu.gameState.clanGold||0;
    const total = distributions.reduce((s,d)=>s+(d.amount||0),0);
    if (total>avail) { send(res, 400, { error: 'Ouro insuficiente. Disponivel: '+avail }); return; }
    const myClan = lu.gameState.clanName;
    distributions.forEach(d => {
      if (!d.amount||d.amount<=0) return;
      const tu = db.users[d.username];
      if (!tu||!tu.gameState||tu.gameState.clanName!==myClan) return;
      tu.gameState.gold = (tu.gameState.gold||0)+d.amount;
      if (!tu.gameState.log) tu.gameState.log=[];
      tu.gameState.log.unshift({ msg:'💰 Recebeu '+d.amount+' ouro do tesouro do cla!', cls:'good' });
    });
    lu.gameState.clanGold -= total;
    saveDB(db);
    broadcastSSE('spoils_distributed', { clan: myClan, total });
    send(res, 200, { ok:true, remaining: lu.gameState.clanGold });
    return;
  }


  // Enviar ouro para outro jogador
  if (method === 'POST' && url === '/api/gold/send') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { targetUsername, amount, message } = await readBody(req);
    if (!targetUsername || !amount || amount <= 0) { send(res, 400, { error: 'Destinatario e valor obrigatorios.' }); return; }
    if (targetUsername.toLowerCase() === username) { send(res, 400, { error: 'Nao pode enviar para si mesmo.' }); return; }
    const db = loadDB();
    const sender = db.users[username];
    const target = db.users[targetUsername.toLowerCase()];
    if (!sender || !sender.gameState) { send(res, 400, { error: 'Personagem nao encontrado.' }); return; }
    if (!target || !target.gameState) { send(res, 404, { error: 'Jogador nao encontrado.' }); return; }
    const amt = Math.floor(amount);
    if (amt < 1) { send(res, 400, { error: 'Valor minimo: 1 ouro.' }); return; }
    if ((sender.gameState.gold || 0) < amt) { send(res, 400, { error: 'Ouro insuficiente. Voce tem ' + (sender.gameState.gold||0) + ' ouro.' }); return; }
    sender.gameState.gold -= amt;
    target.gameState.gold  = (target.gameState.gold || 0) + amt;
    const note = message ? ' ("'+message.slice(0,60)+'")'  : '';
    if (!sender.gameState.log) sender.gameState.log = [];
    if (!target.gameState.log) target.gameState.log = [];
    sender.gameState.log.unshift({ msg: '💸 Enviou ' + amt + ' ouro para ' + target.gameState.name + note, cls: 'info' });
    target.gameState.log.unshift({ msg: '💰 Recebeu ' + amt + ' ouro de ' + sender.gameState.name + note, cls: 'good' });
    saveDB(db);
    broadcastSSE('gold_received', { to: targetUsername.toLowerCase(), from: sender.gameState.name, amount: amt, message: message||'' });
    send(res, 200, { ok: true, newBalance: sender.gameState.gold });
    return;
  }

  // Buscar jogador por username (perfil publico + envio de ouro)
  if (method === 'GET' && url.startsWith('/api/player/')) {
    const viewer = verifyToken(getToken(req)); // may be null for unauthenticated
    const targetUser = url.slice('/api/player/'.length);
    if (!targetUser) { send(res, 400, { error: 'Usuario necessario.' }); return; }
    const db = loadDB();
    const u = db.users[targetUser.toLowerCase()];
    if (!u || !u.gameState) { send(res, 404, { error: 'Jogador nao encontrado.' }); return; }
    const g = u.gameState;
    const isOwner = viewer === targetUser.toLowerCase();
    const isPrivate = g.profilePrivate && !isOwner;
    if (isPrivate) {
      // Return minimal info only
      send(res, 200, {
        username: u.username, name: g.name, race: g.race, level: g.level,
        clanName: g.clanName||null, isPrivate: true,
      });
      return;
    }
    // Full public profile
    send(res, 200, {
      username: u.username, name: g.name, race: g.race, level: g.level,
      clanName: g.clanName||null, clanTag: g.clanTag||null, clanRole: g.clanRole||'member',
      str: g.str||10, dex: g.dex||10, mag: g.mag||8, res: g.res||10,
      power: calcPower(g),
      stats: {
        missions: (g.stats&&g.stats.missions)||0,
        kills: (g.stats&&g.stats.kills)||0,
        pvpWins: (g.stats&&g.stats.pvpWins)||0,
        pvpLosses: (g.stats&&g.stats.pvpLosses)||0,
        warWins: (g.stats&&g.stats.warWins)||0,
        warLosses: (g.stats&&g.stats.warLosses)||0,
        crimes: (g.stats&&g.stats.crimes)||0,
      },
      equipment: isOwner ? g.equipment : g.equipment, // always show equipment
      inventory: isOwner ? (g.inventory||[]) : [],     // inventory only to owner
      achievements: g.achievements||[],
      isPrivate: false,
      isOwner,
    });
    return;
  }


  // ═══════════════════════════════════════════════════════
  // SELL ITEM
  // ═══════════════════════════════════════════════════════
  if (method === 'POST' && url === '/api/item/sell') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { invId } = await readBody(req);
    if (!invId) { send(res, 400, { error: 'invId necessario.' }); return; }
    const db = loadDB();
    const user = db.users[username];
    if (!user || !user.gameState) { send(res, 400, { error: 'Personagem nao encontrado.' }); return; }
    const g = user.gameState;
    const idx = (g.inventory||[]).indexOf(invId);
    if (idx < 0) { send(res, 404, { error: 'Item nao encontrado no inventario.' }); return; }
    // Cannot sell equipped items
    const isEquipped = Object.values(g.equipment||{}).includes(invId);
    if (isEquipped) { send(res, 400, { error: 'Desequipe o item antes de vender.' }); return; }
    // Calculate sell price
    const sellPrice = calcSellPrice(invId);
    g.inventory.splice(idx, 1);
    g.gold = (g.gold||0) + sellPrice;
    if (!g.log) g.log = [];
    g.log.unshift({ msg: '💰 Vendeu item por ' + sellPrice + ' ouro.', cls: 'info' });
    saveDB(db);
    send(res, 200, { ok: true, goldEarned: sellPrice, newBalance: g.gold });
    return;
  }

  // ═══════════════════════════════════════════════════════
  // FRIENDS
  // ═══════════════════════════════════════════════════════
  if (method === 'POST' && url === '/api/friends/add') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { targetUsername } = await readBody(req);
    if (!targetUsername) { send(res, 400, { error: 'targetUsername necessario.' }); return; }
    const target = targetUsername.toLowerCase();
    if (target === username) { send(res, 400, { error: 'Voce nao pode se adicionar.' }); return; }
    const db = loadDB();
    const user = db.users[username];
    const tUser = db.users[target];
    if (!tUser || !tUser.gameState) { send(res, 404, { error: 'Jogador nao encontrado.' }); return; }
    if (!user.gameState) { send(res, 400, { error: 'Crie um personagem primeiro.' }); return; }
    if (!db.friendRequests) db.friendRequests = {};
    // Check if already friends
    const uFriends = user.gameState.friends || [];
    if (uFriends.includes(target)) { send(res, 409, { error: 'Ja sao amigos.' }); return; }
    // Send friend request
    if (!db.friendRequests[target]) db.friendRequests[target] = [];
    if (db.friendRequests[target].includes(username)) { send(res, 409, { error: 'Solicitacao ja enviada.' }); return; }
    db.friendRequests[target].push(username);
    saveDB(db);
    broadcastSSE('friend_request', { to: target, from: username, fromName: user.gameState.name });
    send(res, 200, { ok: true });
    return;
  }

  if (method === 'POST' && url === '/api/friends/respond') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { fromUsername, accept } = await readBody(req);
    const from = fromUsername.toLowerCase();
    const db = loadDB();
    if (!db.friendRequests) db.friendRequests = {};
    const reqs = db.friendRequests[username] || [];
    const idx = reqs.indexOf(from);
    if (idx < 0) { send(res, 404, { error: 'Solicitacao nao encontrada.' }); return; }
    reqs.splice(idx, 1);
    db.friendRequests[username] = reqs;
    if (accept) {
      // Add mutual friendship
      const uUser = db.users[username];
      const fUser = db.users[from];
      if (uUser && uUser.gameState) {
        if (!uUser.gameState.friends) uUser.gameState.friends = [];
        if (!uUser.gameState.friends.includes(from)) uUser.gameState.friends.push(from);
      }
      if (fUser && fUser.gameState) {
        if (!fUser.gameState.friends) fUser.gameState.friends = [];
        if (!fUser.gameState.friends.includes(username)) fUser.gameState.friends.push(username);
      }
      broadcastSSE('friend_accepted', { to: from, by: username, byName: uUser&&uUser.gameState?uUser.gameState.name:'?' });
    }
    saveDB(db);
    send(res, 200, { ok: true, accepted: !!accept });
    return;
  }

  if (method === 'GET' && url === '/api/friends/requests') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const db = loadDB();
    if (!db.friendRequests) { send(res, 200, { requests: [] }); return; }
    const reqs = (db.friendRequests[username] || []).map(from => {
      const u = db.users[from];
      return { username: from, name: u&&u.gameState?u.gameState.name:from, race: u&&u.gameState?u.gameState.race:'humano', level: u&&u.gameState?u.gameState.level:1 };
    });
    send(res, 200, { requests: reqs });
    return;
  }

  if (method === 'GET' && url === '/api/friends/list') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const db = loadDB();
    const user = db.users[username];
    if (!user||!user.gameState) { send(res, 200, { friends: [] }); return; }
    const friends = (user.gameState.friends||[]).map(f => {
      const u = db.users[f];
      if (!u||!u.gameState) return null;
      const g = u.gameState;
      return { username: f, name: g.name, race: g.race, level: g.level, power: calcPower(g), online: onlineMap.has(f) };
    }).filter(Boolean);
    send(res, 200, { friends });
    return;
  }

  if (method === 'POST' && url === '/api/friends/remove') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { targetUsername } = await readBody(req);
    const target = targetUsername.toLowerCase();
    const db = loadDB();
    const user = db.users[username];
    const tUser = db.users[target];
    if (user&&user.gameState&&user.gameState.friends) {
      user.gameState.friends = user.gameState.friends.filter(f=>f!==target);
    }
    if (tUser&&tUser.gameState&&tUser.gameState.friends) {
      tUser.gameState.friends = tUser.gameState.friends.filter(f=>f!==username);
    }
    saveDB(db);
    send(res, 200, { ok: true });
    return;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // SECURE TRADE SYSTEM — Negociacao com confirmacao dupla
  // ═══════════════════════════════════════════════════════════════════════

  if (method === 'POST' && url === '/api/trade/invite') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { targetUsername } = await readBody(req);
    const target = (targetUsername||'').toLowerCase();
    if (!target || target === username) { send(res, 400, { error: 'Alvo invalido.' }); return; }
    const db = loadDB();
    const user  = db.users[username];
    const tUser = db.users[target];
    if (!user||!user.gameState)  { send(res, 400, { error: 'Crie um personagem primeiro.' }); return; }
    if (!tUser||!tUser.gameState){ send(res, 404, { error: 'Jogador nao encontrado.' }); return; }
    if (!(user.gameState.friends||[]).includes(target)) { send(res, 403, { error: 'Somente amigos podem fazer trade.' }); return; }
    if (!onlineMap.has(target)) { send(res, 400, { error: tUser.gameState.name + ' nao esta online agora.' }); return; }
    if (!db.trades) db.trades = {};
    const existing = Object.values(db.trades).find(t =>
      t.status !== 'done' && t.status !== 'cancelled' &&
      (t.sideA.username===username||t.sideB.username===username||t.sideA.username===target||t.sideB.username===target)
    );
    if (existing) { send(res, 409, { error: 'Um dos jogadores ja esta em um trade ativo.' }); return; }
    const tradeId = crypto.randomBytes(8).toString('hex');
    const trade = {
      id: tradeId, status: 'invited',
      sideA: { username, name: user.gameState.name,  items: [], gold: 0, ready: false },
      sideB: { username: target, name: tUser.gameState.name, items: [], gold: 0, ready: false },
      createdAt: Date.now(), expiresAt: Date.now() + 180000, log: [],
    };
    db.trades[tradeId] = trade;
    saveDB(db);
    sendSSE(target, 'trade_invite', { trade });
    send(res, 200, { ok: true, tradeId, trade });
    return;
  }

  if (method === 'POST' && url === '/api/trade/respond') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { tradeId, accept } = await readBody(req);
    const db = loadDB();
    if (!db.trades||!db.trades[tradeId]) { send(res, 404, { error: 'Trade nao encontrado.' }); return; }
    const trade = db.trades[tradeId];
    if (trade.sideB.username !== username) { send(res, 403, { error: 'Este trade nao e para voce.' }); return; }
    if (trade.status !== 'invited') { send(res, 400, { error: 'Trade ja respondido.' }); return; }
    if (Date.now() > trade.expiresAt) { trade.status='cancelled'; saveDB(db); send(res,400,{error:'Convite expirou.'}); return; }
    if (!accept) {
      trade.status = 'cancelled'; trade.log.push(trade.sideB.name + ' recusou o trade.');
      saveDB(db); sendSSE(trade.sideA.username, 'trade_update', { trade });
      send(res, 200, { ok: true, result: 'declined' }); return;
    }
    trade.status = 'active'; trade.expiresAt = Date.now() + 180000;
    trade.log.push('Trade iniciado! Ambos podem adicionar itens e ouro.');
    saveDB(db);
    broadcastTrade(trade, 'trade_update');
    send(res, 200, { ok: true, trade }); return;
  }

  if (method === 'POST' && url === '/api/trade/offer') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { tradeId, items, gold } = await readBody(req);
    const db = loadDB();
    if (!db.trades||!db.trades[tradeId]) { send(res, 404, { error: 'Trade nao encontrado.' }); return; }
    const trade = db.trades[tradeId];
    if (trade.status !== 'active') { send(res, 400, { error: 'Trade nao esta ativo.' }); return; }
    if (Date.now() > trade.expiresAt) { trade.status='cancelled'; saveDB(db); broadcastTrade(trade,'trade_update'); send(res,400,{error:'Trade expirou.'}); return; }
    const isA = trade.sideA.username === username;
    const isB = trade.sideB.username === username;
    if (!isA && !isB) { send(res, 403, { error: 'Voce nao faz parte deste trade.' }); return; }
    const side = isA ? trade.sideA : trade.sideB;
    const g = db.users[username].gameState;
    const goldVal = Math.max(0, Math.floor(gold||0));
    if (goldVal > (g.gold||0)) { send(res, 400, { error: 'Ouro insuficiente. Voce tem ' + (g.gold||0) + '.' }); return; }
    const itemList = Array.isArray(items) ? items : [];
    for (const invId of itemList) {
      if (!(g.inventory||[]).includes(invId)) { send(res, 400, { error: 'Item nao esta no seu inventario.' }); return; }
      if (Object.values(g.equipment||{}).includes(invId)) { send(res, 400, { error: 'Desequipe o item antes de colocar no trade.' }); return; }
    }
    side.items = itemList; side.gold = goldVal; side.ready = false;
    trade.log.push(side.name + ' atualizou a oferta.'); trade.expiresAt = Date.now() + 180000;
    saveDB(db); broadcastTrade(trade, 'trade_update');
    send(res, 200, { ok: true, trade }); return;
  }

  if (method === 'POST' && url === '/api/trade/confirm') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { tradeId } = await readBody(req);
    const db = loadDB();
    if (!db.trades||!db.trades[tradeId]) { send(res, 404, { error: 'Trade nao encontrado.' }); return; }
    const trade = db.trades[tradeId];
    if (trade.status !== 'active') { send(res, 400, { error: 'Trade nao esta ativo.' }); return; }
    if (Date.now() > trade.expiresAt) { trade.status='cancelled'; saveDB(db); broadcastTrade(trade,'trade_update'); send(res,400,{error:'Trade expirou.'}); return; }
    const isA = trade.sideA.username === username;
    const isB = trade.sideB.username === username;
    if (!isA && !isB) { send(res, 403, { error: 'Voce nao faz parte deste trade.' }); return; }
    const side = isA ? trade.sideA : trade.sideB;
    side.ready = true; trade.log.push(side.name + ' confirmou. OK ✓');
    if (trade.sideA.ready && trade.sideB.ready) {
      const gA = db.users[trade.sideA.username].gameState;
      const gB = db.users[trade.sideB.username].gameState;
      const valid = (
        (gA.gold||0) >= trade.sideA.gold && (gB.gold||0) >= trade.sideB.gold &&
        trade.sideA.items.every(id => (gA.inventory||[]).includes(id) && !Object.values(gA.equipment||{}).includes(id)) &&
        trade.sideB.items.every(id => (gB.inventory||[]).includes(id) && !Object.values(gB.equipment||{}).includes(id))
      );
      if (!valid) {
        trade.status = 'cancelled'; trade.log.push('CANCELADO: item ou ouro nao disponivel.');
        saveDB(db); broadcastTrade(trade,'trade_update');
        send(res, 400, { error: 'Item ou ouro nao esta mais disponivel.' }); return;
      }
      gA.gold = (gA.gold||0) - trade.sideA.gold + trade.sideB.gold;
      gB.gold = (gB.gold||0) - trade.sideB.gold + trade.sideA.gold;
      trade.sideA.items.forEach(id => { const i=gA.inventory.indexOf(id); if(i>=0)gA.inventory.splice(i,1); if(!gB.inventory)gB.inventory=[]; gB.inventory.push(id); });
      trade.sideB.items.forEach(id => { const i=gB.inventory.indexOf(id); if(i>=0)gB.inventory.splice(i,1); if(!gA.inventory)gA.inventory=[]; gA.inventory.push(id); });
      const sa = (trade.sideA.items.length?trade.sideA.items.length+' item(s)':'') + (trade.sideA.gold?' +\u20a1'+trade.sideA.gold:'') || 'nada';
      const sb = (trade.sideB.items.length?trade.sideB.items.length+' item(s)':'') + (trade.sideB.gold?' +\u20a1'+trade.sideB.gold:'') || 'nada';
      if(!gA.log)gA.log=[]; gA.log.unshift({msg:'\uD83E\uDD1D Trade com '+trade.sideB.name+': enviou ['+sa+'] recebeu ['+sb+']',cls:'good'});
      if(!gB.log)gB.log=[]; gB.log.unshift({msg:'\uD83E\uDD1D Trade com '+trade.sideA.name+': enviou ['+sb+'] recebeu ['+sa+']',cls:'good'});
      trade.status = 'done'; trade.completedAt = Date.now(); trade.log.push('TRADE CONCLUIDO!');
      saveDB(db); broadcastTrade(trade, 'trade_done');
    } else {
      saveDB(db); broadcastTrade(trade, 'trade_update');
    }
    send(res, 200, { ok: true, trade }); return;
  }

  if (method === 'POST' && url === '/api/trade/cancel') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { tradeId } = await readBody(req);
    const db = loadDB();
    if (!db.trades||!db.trades[tradeId]) { send(res, 404, { error: 'Trade nao encontrado.' }); return; }
    const trade = db.trades[tradeId];
    if (trade.status==='done'||trade.status==='cancelled') { send(res, 400, { error: 'Trade ja encerrado.' }); return; }
    const name = trade.sideA.username===username ? trade.sideA.name : trade.sideB.name;
    trade.status = 'cancelled'; trade.log.push(name + ' cancelou o trade.');
    saveDB(db); broadcastTrade(trade, 'trade_update');
    send(res, 200, { ok: true }); return;
  }

  if (method === 'GET' && url.startsWith('/api/trade/state/')) {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const tradeId = url.slice('/api/trade/state/'.length);
    const db = loadDB();
    if (!db.trades||!db.trades[tradeId]) { send(res, 404, { error: 'Trade nao encontrado.' }); return; }
    send(res, 200, { trade: db.trades[tradeId] }); return;
  }


  // ═══════════════════════════════════════════════════════════════════════
  // CHAT SYSTEM  (DM | group | clan)
  // ═══════════════════════════════════════════════════════════════════════
  // GET  /api/chat/rooms          — lista salas do usuario
  // POST /api/chat/room/create    — criar sala (dm | group | clan)
  // GET  /api/chat/room/:id       — mensagens da sala
  // POST /api/chat/room/:id/send  — enviar mensagem
  // POST /api/chat/group/invite   — convidar para grupo

  if (method === 'GET' && url === '/api/chat/rooms') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const db = loadDB();
    if (!db.chatRooms) db.chatRooms = {};
    const rooms = Object.values(db.chatRooms)
      .filter(r => r.members.includes(username))
      .map(r => {
        const last = r.messages.length ? r.messages[r.messages.length-1] : null;
        const unread = (r.messages||[]).filter(m => m.ts > ((r.readAt||{})[username]||0) && m.from !== username).length;
        return { id: r.id, type: r.type, name: r.name, members: r.members, unread, lastMsg: last ? {text: last.text.slice(0,40), from: last.fromName, ts: last.ts} : null };
      }).sort((a,b) => (b.lastMsg?.ts||0)-(a.lastMsg?.ts||0));
    send(res, 200, { rooms });
    return;
  }

  if (method === 'POST' && url === '/api/chat/room/create') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { type, targetUsername, name } = await readBody(req);
    const db = loadDB();
    if (!db.chatRooms) db.chatRooms = {};
    if (!db.users[username]||!db.users[username].gameState) { send(res,400,{error:'Personagem nao encontrado.'}); return; }
    const myName = db.users[username].gameState.name;

    if (type === 'dm') {
      const target = (targetUsername||'').toLowerCase();
      if (!target || target === username) { send(res,400,{error:'Alvo invalido.'}); return; }
      if (!db.users[target]||!db.users[target].gameState) { send(res,404,{error:'Jogador nao encontrado.'}); return; }
      // Check existing DM room
      const existing = Object.values(db.chatRooms).find(r => r.type==='dm' && r.members.includes(username) && r.members.includes(target));
      if (existing) { send(res,200,{room: existing}); return; }
      const room = { id: 'dm_'+crypto.randomBytes(6).toString('hex'), type:'dm', name:'DM', members:[username,target], messages:[], readAt:{}, createdAt:Date.now() };
      db.chatRooms[room.id] = room;
      saveDB(db);
      sendSSE(target, 'chat_new_room', { room: { id:room.id, type:'dm', name:myName, members:room.members, unread:0, lastMsg:null } });
      send(res,200,{room}); return;
    }

    if (type === 'group') {
      const roomName = (name||'Grupo').slice(0,30);
      const room = { id: 'grp_'+crypto.randomBytes(6).toString('hex'), type:'group', name:roomName, members:[username], messages:[], readAt:{}, createdAt:Date.now(), admin:username };
      db.chatRooms[room.id] = room;
      saveDB(db);
      send(res,200,{room}); return;
    }

    if (type === 'clan') {
      const g = db.users[username].gameState;
      if (!g.clanName) { send(res,400,{error:'Voce nao possui um cla.'}); return; }
      // Find or create clan room
      const existing = Object.values(db.chatRooms).find(r => r.type==='clan' && r.clanName===g.clanName);
      if (existing) { send(res,200,{room:existing}); return; }
      const room = { id:'clan_'+crypto.randomBytes(6).toString('hex'), type:'clan', name:'Clã '+g.clanName, clanName:g.clanName, members:[username], messages:[], readAt:{}, createdAt:Date.now() };
      db.chatRooms[room.id] = room;
      saveDB(db);
      send(res,200,{room}); return;
    }

    send(res,400,{error:'Tipo invalido.'}); return;
  }

  if (method === 'POST' && url === '/api/chat/group/invite') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { roomId, targetUsername } = await readBody(req);
    const db = loadDB();
    if (!db.chatRooms||!db.chatRooms[roomId]) { send(res,404,{error:'Sala nao encontrada.'}); return; }
    const room = db.chatRooms[roomId];
    if (room.type!=='group') { send(res,400,{error:'Apenas grupos podem convidar.'}); return; }
    if (room.admin!==username) { send(res,403,{error:'Apenas o admin pode convidar.'}); return; }
    const target = (targetUsername||'').toLowerCase();
    if (!db.users[target]||!db.users[target].gameState) { send(res,404,{error:'Jogador nao encontrado.'}); return; }
    if (room.members.includes(target)) { send(res,409,{error:'Jogador ja esta no grupo.'}); return; }
    room.members.push(target);
    saveDB(db);
    const myName = db.users[username].gameState.name;
    sendSSE(target,'chat_new_room',{room:{id:room.id,type:'group',name:room.name,members:room.members,unread:0,lastMsg:null}});
    send(res,200,{ok:true}); return;
  }

  if (method === 'GET' && url.startsWith('/api/chat/room/') && !url.includes('/send')) {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const roomId = url.slice('/api/chat/room/'.length);
    const db = loadDB();
    if (!db.chatRooms||!db.chatRooms[roomId]) { send(res,404,{error:'Sala nao encontrada.'}); return; }
    const room = db.chatRooms[roomId];
    if (!room.members.includes(username)) { send(res,403,{error:'Voce nao e membro desta sala.'}); return; }
    // Mark read
    if (!room.readAt) room.readAt = {};
    room.readAt[username] = Date.now();
    saveDB(db);
    send(res,200,{room, messages: room.messages.slice(-100)}); return;
  }

  if (method === 'POST' && url.match(/^\/api\/chat\/room\/[^/]+\/send$/)) {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const roomId = url.split('/')[4];
    const { text } = await readBody(req);
    if (!text||!text.trim()) { send(res,400,{error:'Mensagem vazia.'}); return; }
    const db = loadDB();
    if (!db.chatRooms||!db.chatRooms[roomId]) { send(res,404,{error:'Sala nao encontrada.'}); return; }
    const room = db.chatRooms[roomId];
    if (!room.members.includes(username)) { send(res,403,{error:'Nao e membro.'}); return; }
    // Auto-sync clan room members
    if (room.type==='clan') {
      const allUsers = Object.values(db.users).filter(u=>u.gameState&&u.gameState.clanName===room.clanName);
      allUsers.forEach(u=>{ if(!room.members.includes(u.username)) room.members.push(u.username); });
    }
    const g = db.users[username].gameState;
    const msg = { id: crypto.randomBytes(4).toString('hex'), from: username, fromName: g.name, fromRace: g.race, text: text.trim().slice(0,500), ts: Date.now() };
    room.messages.push(msg);
    if (room.messages.length > 200) room.messages = room.messages.slice(-200);
    if (!room.readAt) room.readAt = {};
    room.readAt[username] = Date.now();
    saveDB(db);
    // Notify all members
    room.members.forEach(m => { if (m!==username) sendSSE(m,'chat_message',{roomId, msg, roomName:room.name, roomType:room.type}); });
    send(res,200,{ok:true,msg}); return;
  }


  // ═══════════════════════════════════════════════════════════════════════
  // CLAN ROLES  (leader assigns: mestre_batalha | general | assassino auto)
  // ═══════════════════════════════════════════════════════════════════════
  if (method === 'POST' && url === '/api/clan/set-role') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { targetUsername, role } = await readBody(req);
    const VALID_ROLES = ['member','mestre_batalha','general'];
    if (!VALID_ROLES.includes(role)) { send(res,400,{error:'Cargo invalido. Use: member | mestre_batalha | general'}); return; }
    const db = loadDB();
    const user = db.users[username];
    if (!user||!user.gameState||user.gameState.clanRole!=='leader') { send(res,403,{error:'Apenas o lider pode alterar cargos.'}); return; }
    const myClan = user.gameState.clanName;
    const target = (targetUsername||'').toLowerCase();
    const tUser = db.users[target];
    if (!tUser||!tUser.gameState||tUser.gameState.clanName!==myClan) { send(res,404,{error:'Jogador nao e membro do cla.'}); return; }
    if (target === username) { send(res,400,{error:'Nao pode alterar seu proprio cargo.'}); return; }
    tUser.gameState.clanRole = role;
    saveDB(db);
    send(res,200,{ok:true, username: target, newRole: role});
    return;
  }

  // Get clan members list with roles
  if (method === 'GET' && url.startsWith('/api/clan/members')) {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const db = loadDB();
    const user = db.users[username];
    if (!user||!user.gameState||!user.gameState.clanName) { send(res,400,{error:'Sem cla.'}); return; }
    const myClan = user.gameState.clanName;
    // Find all members
    const members = Object.entries(db.users)
      .filter(([u,d])=>d.gameState&&d.gameState.clanName===myClan)
      .map(([u,d])=>{
        const g=d.gameState;
        return { username:u, name:g.name, race:g.race, level:g.level, clanRole:g.clanRole||'member',
          pvpKills:g.stats?g.stats.pvpWins||0:0, power:calcPower(g), online:onlineMap.has(u) };
      });
    // Auto-assign assassin = highest pvpWins, but only if 2+ members
    if (members.length >= 2) {
      const nonLeaders = members.filter(m=>m.clanRole!=='leader');
      const topKiller = nonLeaders.sort((a,b)=>b.pvpKills-a.pvpKills)[0];
      if (topKiller && topKiller.pvpKills > 0) {
        // Only auto-flag, don't write to DB here — just annotate in response
        topKiller.autoAssassin = true;
      }
    }
    send(res,200,{members}); return;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // TAVERN DUEL  (both online, attacker & defender in tavern)
  // Higher power wins. Winner +10 random stat, loser -10 random stat + infirmary 10min
  // Same clan = blocked
  // ═══════════════════════════════════════════════════════════════════════
  if (method === 'POST' && url === '/api/tavern/duel') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { targetUsername } = await readBody(req);
    const target = (targetUsername||'').toLowerCase();
    const db = loadDB();
    const user  = db.users[username];
    const tUser = db.users[target];
    if (!user||!user.gameState)   { send(res,400,{error:'Personagem nao encontrado.'}); return; }
    if (!tUser||!tUser.gameState) { send(res,404,{error:'Alvo nao encontrado.'}); return; }
    const g  = user.gameState;
    const gt = tUser.gameState;
    // Same clan block
    if (g.clanName && g.clanName === gt.clanName) { send(res,400,{error:'Membros do mesmo cla nao podem se atacar!'}); return; }
    // Both must be online
    if (!onlineMap.has(target)) { send(res,400,{error:gt.name+' nao esta online.'}); return; }
    // Attacker must not be in infirmary
    if (g.knockedOutUntil && g.knockedOutUntil > Date.now()) { send(res,400,{error:'Voce esta na enfermaria!'}); return; }
    // Defender must not be in infirmary
    if (gt.knockedOutUntil && gt.knockedOutUntil > Date.now()) { send(res,400,{error:gt.name+' esta na enfermaria se recuperando.'}); return; }

    const myPower  = calcPower(g);
    const hisPower = calcPower(gt);
    const STATS = ['str','dex','mag','res'];
    const randStat = () => STATS[Math.floor(Math.random()*STATS.length)];

    let winner, loser, winG, loseG;
    if (myPower >= hisPower) {
      winner=username; loser=target; winG=g; loseG=gt;
    } else {
      winner=target; loser=username; winG=gt; loseG=g;
    }
    // Winner: +10 to random stat
    const winStat = randStat();
    winG[winStat] = (winG[winStat]||10) + 10;
    if (!winG.stats) winG.stats={};
    winG.stats.pvpWins = (winG.stats.pvpWins||0)+1;
    if (!winG.log) winG.log=[];
    winG.log.unshift({msg:'⚔ Duelo na Taverna: venceu contra '+loseG.name+'! +10 '+winStat.toUpperCase(), cls:'good'});

    // Loser: -10 random stat (min 1) + infirmary 10min
    const loseStat = randStat();
    loseG[loseStat] = Math.max(1, (loseG[loseStat]||10) - 10);
    if (!loseG.stats) loseG.stats={};
    loseG.stats.pvpLosses = (loseG.stats.pvpLosses||0)+1;
    loseG.knockedOutUntil = Date.now() + 10*60*1000; // 10 min
    loseG.hp = Math.max(1, Math.floor(loseG.hpMax * 0.1)); // reduced to 10% hp
    if (!loseG.log) loseG.log=[];
    loseG.log.unshift({msg:'💀 Duelo na Taverna: perdeu para '+winG.name+'. -10 '+loseStat.toUpperCase()+'. Enfermaria 10min.', cls:'bad'});

    saveDB(db);
    // Notify both via SSE
    sendSSE(winner,'tavern_duel_result',{result:'win', vs:loseG.name, stat:winStat, power:{mine:myPower,theirs:hisPower}});
    sendSSE(loser, 'tavern_duel_result',{result:'loss',vs:winG.name, stat:loseStat, knockedOutUntil:loseG.knockedOutUntil, power:{mine:hisPower,theirs:myPower}});
    send(res,200,{ok:true, winner, loser, winStat, loseStat, myPower, hisPower}); return;
  }

  // Pay to leave infirmary early
  if (method === 'POST' && url === '/api/tavern/revive') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const db = loadDB();
    const user = db.users[username];
    if (!user||!user.gameState) { send(res,400,{error:'Personagem nao encontrado.'}); return; }
    const g = user.gameState;
    if (!g.knockedOutUntil || g.knockedOutUntil <= Date.now()) { send(res,400,{error:'Nao esta na enfermaria.'}); return; }
    const REVIVE_COST = 3000;
    if ((g.gold||0) < REVIVE_COST) { send(res,400,{error:'Precisa de 3.000 ouro para reviver agora.'}); return; }
    g.gold -= REVIVE_COST;
    g.knockedOutUntil = 0;
    g.hp = g.hpMax;
    if (!g.log) g.log=[];
    g.log.unshift({msg:'💊 Pagou 3.000 ouro para sair da enfermaria.', cls:'info'});
    saveDB(db);
    send(res,200,{ok:true, newBalance:g.gold}); return;
  }


  // ═══════════════════════════════════════════════════════════════════════
  // GLOBAL CHAT — Chat do Reino (open to all players)
  // ═══════════════════════════════════════════════════════════════════════
  if (method === 'GET' && url === '/api/chat/global') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const db = loadDB();
    if (!db.chatRooms) db.chatRooms = {};
    // Find or create the single global room
    let globalRoom = Object.values(db.chatRooms).find(r => r.type === 'global');
    if (!globalRoom) {
      globalRoom = {
        id: 'global_reino',
        type: 'global',
        name: 'Chat do Reino',
        members: [],   // all players — no restriction
        messages: [],
        readAt: {},
        createdAt: Date.now(),
      };
      db.chatRooms['global_reino'] = globalRoom;
      saveDB(db);
    }
    // Mark read
    if (!globalRoom.readAt) globalRoom.readAt = {};
    globalRoom.readAt[username] = Date.now();
    saveDB(db);
    send(res, 200, { room: globalRoom, messages: globalRoom.messages.slice(-100) });
    return;
  }

  if (method === 'POST' && url === '/api/chat/global/send') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { text } = await readBody(req);
    if (!text || !text.trim()) { send(res, 400, { error: 'Mensagem vazia.' }); return; }
    const db = loadDB();
    if (!db.chatRooms) db.chatRooms = {};
    let globalRoom = Object.values(db.chatRooms).find(r => r.type === 'global');
    if (!globalRoom) {
      globalRoom = { id:'global_reino', type:'global', name:'Chat do Reino', members:[], messages:[], readAt:{}, createdAt:Date.now() };
      db.chatRooms['global_reino'] = globalRoom;
    }
    const g = db.users[username] && db.users[username].gameState;
    if (!g) { send(res, 400, { error: 'Personagem nao encontrado.' }); return; }
    const msg = {
      id: crypto.randomBytes(4).toString('hex'),
      from: username,
      fromName: g.name,
      fromRace: g.race,
      clanTag: g.clanTag || null,
      clanRole: g.clanRole || 'member',
      level: g.level || 1,
      text: text.trim().slice(0, 300),
      ts: Date.now(),
    };
    globalRoom.messages.push(msg);
    if (globalRoom.messages.length > 300) globalRoom.messages = globalRoom.messages.slice(-300);
    if (!globalRoom.readAt) globalRoom.readAt = {};
    globalRoom.readAt[username] = Date.now();
    saveDB(db);
    // Broadcast to ALL online players
    broadcastSSE('global_chat_message', { msg });
    send(res, 200, { ok: true, msg });
    return;
  }


  // ═══════════════════════════════════════════════════════════════════════
  // MISSION COMPLETE — Server tracks global counter, drops milestone stones
  // Called by client after finalizeCombat win
  // ═══════════════════════════════════════════════════════════════════════
  if (method === 'POST' && url === '/api/mission/complete') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { missionType } = await readBody(req);
    const db = loadDB();
    const user = db.users[username];
    if (!user || !user.gameState) { send(res, 400, { error: 'Personagem nao encontrado.' }); return; }

    // ── Global mission counter ──────────────────────────────────────────
    if (!db.globalStats) db.globalStats = { totalMissions: 0, pristMilestone: 0, ravikaMilestone: 0 };
    db.globalStats.totalMissions++;
    const total = db.globalStats.totalMissions;

    let stoneDropped = null;

    // Every 300 missions: alternates Prist / Ravika
    // milestone 300: prist_s, 600: ravika_s, 900: prist_s, 1200: ravika_s ...
    if (total % 300 === 0) {
      const cyclePos = Math.floor(total / 300) % 2; // 0=prist, 1=ravika
      stoneDropped = cyclePos === 0 ? 'prist_s' : 'ravika_s';

      // Give the stone to the player who completed this milestone mission
      const g = user.gameState;
      if (!g.consumables) g.consumables = [];
      g.consumables.push(stoneDropped);
      if (!g.log) g.log = [];
      const stoneName = stoneDropped === 'prist_s' ? 'Pedra Prist 💠' : 'Pedra Ravika 🌑';
      g.log.unshift({ msg: '🎉 MARCO! Missão #'+total+' do servidor! Você recebeu: '+stoneName, cls:'good' });

      saveDB(db);

      // Only notify the winner — silent for everyone else (it's a surprise!)
      sendSSE(username, 'server_milestone', {
        stoneId: stoneDropped,
        stoneName,
        winnerUsername: username,
      });
    } else {
      saveDB(db);
    }

    // Return minimal info — don't expose the global counter to client
    send(res, 200, { ok: true, stoneDropped });
    return;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // RAID COMPLETE — Drop 2 Prist stones split among raid participants
  // Client sends the list of participants after a raid win
  // ═══════════════════════════════════════════════════════════════════════
  if (method === 'POST' && url === '/api/raid/complete') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { participants } = await readBody(req);  // array of usernames
    if (!Array.isArray(participants) || participants.length < 1) { send(res,400,{error:'Participants necessario.'}); return; }
    const db = loadDB();
    if (!db.globalStats) db.globalStats = { totalMissions: 0, pristMilestone: 0, ravikaMilestone: 0 };
    db.globalStats.totalMissions++;

    // Pick 2 random winners from participants (no repeats)
    const pool = [...participants];
    const winners = [];
    const STONES_TO_DROP = Math.min(2, pool.length);
    while (winners.length < STONES_TO_DROP && pool.length > 0) {
      const idx = Math.floor(Math.random() * pool.length);
      winners.push(pool.splice(idx, 1)[0]);
    }

    const results = [];
    for (const winnerUsername of winners) {
      const wUser = db.users[winnerUsername.toLowerCase()];
      if (!wUser || !wUser.gameState) continue;
      const g = wUser.gameState;
      if (!g.consumables) g.consumables = [];
      // Raid drops Prist Reforçada (better stone)
      g.consumables.push('prist_m');
      if (!g.log) g.log = [];
      g.log.unshift({ msg: '🌋 Raid concluída! Você recebeu: Prist Reforçada 🔷', cls:'good' });
      results.push({ username: winnerUsername, name: g.name, stone: 'prist_m' });
      sendSSE(winnerUsername.toLowerCase(), 'raid_stone_drop', { stone: 'prist_m', stoneName: 'Prist Reforçada 🔷' });
    }

    saveDB(db);

    // Notify all participants of results
    const winnerNames = results.map(r => r.name).join(', ');
    participants.forEach(p => {
      sendSSE(p.toLowerCase(), 'raid_result', {
        winners: results,
        msg: '🌋 Raid concluída! Pedras para: ' + (winnerNames || 'ninguém') + '.'
      });
    });

    send(res, 200, { ok: true, winners: results, totalParticipants: participants.length });
    return;
  }

  // globalstats endpoint removed — counter is server-side only


  // ═══════════════════════════════════════════════════════════════════════
  // CLAN MANAGEMENT — join requests, open/closed, kick
  // ═══════════════════════════════════════════════════════════════════════

  // Toggle clan open/closed
  if (method === 'POST' && url === '/api/clan/settings') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { isOpen } = await readBody(req);
    const db = loadDB();
    const user = db.users[username];
    if (!user||!user.gameState||user.gameState.clanRole!=='leader') { send(res,403,{error:'Apenas o lider pode alterar configuracoes.'}); return; }
    const clanName = user.gameState.clanName;
    // Store setting on leader's gameState (acts as clan config)
    user.gameState.clanOpen = !!isOpen;
    saveDB(db);
    send(res,200,{ok:true, clanOpen: user.gameState.clanOpen});
    return;
  }

  // Request to join clan
  if (method === 'POST' && url === '/api/clan/request') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { clanName } = await readBody(req);
    const db = loadDB();
    const user = db.users[username];
    if (!user||!user.gameState) { send(res,400,{error:'Personagem nao encontrado.'}); return; }
    if (user.gameState.clanName) { send(res,400,{error:'Voce ja pertence a um cla.'}); return; }
    // Find clan leader
    const leaderEntry = Object.entries(db.users).find(([u,d]) => d.gameState&&d.gameState.clanName===clanName&&d.gameState.clanRole==='leader');
    if (!leaderEntry) { send(res,404,{error:'Cla nao encontrado.'}); return; }
    const [leaderUsername, leaderData] = leaderEntry;
    const leaderG = leaderData.gameState;
    // If clan is open: join immediately
    if (leaderG.clanOpen) {
      user.gameState.clanName = clanName;
      user.gameState.clanTag  = leaderG.clanTag;
      user.gameState.clanRole = 'member';
      user.gameState.clanWins = 0;
      user.gameState.clanGold = 0;
      saveDB(db);
      sendSSE(leaderUsername,'clan_member_joined',{name:user.gameState.name,username});
      send(res,200,{ok:true, joined:true, clanTag: leaderG.clanTag});
      return;
    }
    // Clan is closed: store join request
    if (!db.clanRequests) db.clanRequests = {};
    if (!db.clanRequests[clanName]) db.clanRequests[clanName] = [];
    if (db.clanRequests[clanName].find(r=>r.username===username)) { send(res,409,{error:'Solicitacao ja enviada.'}); return; }
    db.clanRequests[clanName].push({ username, name: user.gameState.name, race: user.gameState.race, level: user.gameState.level, ts: Date.now() });
    saveDB(db);
    sendSSE(leaderUsername,'clan_join_request',{applicant: user.gameState.name, username, clanName});
    send(res,200,{ok:true, joined:false, pending:true});
    return;
  }

  // Leader: get pending join requests
  if (method === 'GET' && url === '/api/clan/requests') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const db = loadDB();
    const user = db.users[username];
    if (!user||!user.gameState||user.gameState.clanRole!=='leader') { send(res,403,{error:'Apenas o lider pode ver solicitacoes.'}); return; }
    const clanName = user.gameState.clanName;
    const requests = (db.clanRequests||{})[clanName] || [];
    send(res,200,{requests});
    return;
  }

  // Leader: respond to join request
  if (method === 'POST' && url === '/api/clan/respond') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { applicantUsername, accept } = await readBody(req);
    const db = loadDB();
    const user = db.users[username];
    if (!user||!user.gameState||user.gameState.clanRole!=='leader') { send(res,403,{error:'Apenas o lider pode aprovar.'}); return; }
    const clanName = user.gameState.clanName;
    if (!db.clanRequests) db.clanRequests = {};
    const reqs = db.clanRequests[clanName] || [];
    const idx = reqs.findIndex(r=>r.username===applicantUsername);
    if (idx < 0) { send(res,404,{error:'Solicitacao nao encontrada.'}); return; }
    reqs.splice(idx,1);
    db.clanRequests[clanName] = reqs;
    if (accept) {
      const aUser = db.users[applicantUsername];
      if (aUser&&aUser.gameState) {
        aUser.gameState.clanName = clanName;
        aUser.gameState.clanTag  = user.gameState.clanTag;
        aUser.gameState.clanRole = 'member';
        aUser.gameState.clanWins = 0;
        aUser.gameState.clanGold = 0;
      }
      sendSSE(applicantUsername,'clan_request_answered',{accepted:true, clanName, clanTag:user.gameState.clanTag});
    } else {
      sendSSE(applicantUsername,'clan_request_answered',{accepted:false, clanName});
    }
    saveDB(db);
    send(res,200,{ok:true, accepted:!!accept});
    return;
  }

  // Leader: kick member
  if (method === 'POST' && url === '/api/clan/kick') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { targetUsername } = await readBody(req);
    const db = loadDB();
    const user = db.users[username];
    if (!user||!user.gameState||user.gameState.clanRole!=='leader') { send(res,403,{error:'Apenas o lider pode expulsar.'}); return; }
    const clanName = user.gameState.clanName;
    const target = (targetUsername||'').toLowerCase();
    if (target === username) { send(res,400,{error:'Voce nao pode se expulsar.'}); return; }
    const tUser = db.users[target];
    if (!tUser||!tUser.gameState||tUser.gameState.clanName!==clanName) { send(res,404,{error:'Membro nao encontrado.'}); return; }
    tUser.gameState.clanName = null;
    tUser.gameState.clanTag  = null;
    tUser.gameState.clanRole = 'member';
    saveDB(db);
    sendSSE(target,'clan_kicked',{clanName, byName: user.gameState.name});
    send(res,200,{ok:true});
    return;
  }

  // Leave clan (actual server-side)
  if (method === 'POST' && url === '/api/clan/leave') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const db = loadDB();
    const user = db.users[username];
    if (!user||!user.gameState||!user.gameState.clanName) { send(res,400,{error:'Nao esta em nenhum cla.'}); return; }
    if (user.gameState.clanRole==='leader') { send(res,400,{error:'Lider nao pode sair. Dissolva o cla ou transfira a lideranca.'}); return; }
    const clanName = user.gameState.clanName;
    user.gameState.clanName = null;
    user.gameState.clanTag  = null;
    user.gameState.clanRole = 'member';
    saveDB(db);
    send(res,200,{ok:true});
    return;
  }


  // ═══════════════════════════════════════════════════════════════════════
  // PARTY SYSTEM — Group up to help weaker players level up
  // Distribution table:
  //   2 ppl: 85/15 (organizer/others)
  //   3 ppl: 70/15/15
  //   4 ppl: 55/15/15/15
  //   5 ppl: BONUS — total goes to 270%! 120/50/50/50/50
  // ═══════════════════════════════════════════════════════════════════════

  if (method === 'POST' && url === '/api/party/create') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const db = loadDB();
    const user = db.users[username];
    if (!user||!user.gameState) { send(res,400,{error:'Personagem nao encontrado.'}); return; }
    if (!db.parties) db.parties = {};
    // Check if already in a party
    const existing = Object.values(db.parties).find(p => p.members.some(m => m.username === username));
    if (existing) { send(res,409,{error:'Voce ja esta em uma party.'}); return; }
    const partyId = crypto.randomBytes(6).toString('hex');
    const party = {
      id: partyId,
      leader: username,
      members: [{ username, name: user.gameState.name, race: user.gameState.race, level: user.gameState.level }],
      maxSize: 5,
      createdAt: Date.now(),
      pendingInvites: [],
    };
    db.parties[partyId] = party;
    saveDB(db);
    send(res,200,{ok:true, party});
    return;
  }

  if (method === 'POST' && url === '/api/party/invite') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { targetUsername } = await readBody(req);
    const target = (targetUsername||'').toLowerCase();
    if (target === username) { send(res,400,{error:'Voce nao pode se convidar.'}); return; }
    const db = loadDB();
    if (!db.parties) db.parties = {};
    const party = Object.values(db.parties).find(p => p.leader === username);
    if (!party) { send(res,404,{error:'Voce nao e lider de uma party.'}); return; }
    if (party.members.length >= party.maxSize) { send(res,400,{error:'Party cheia (max 5).'}); return; }
    if (party.members.some(m => m.username === target)) { send(res,409,{error:'Jogador ja esta na party.'}); return; }
    if (party.pendingInvites.includes(target)) { send(res,409,{error:'Convite ja enviado.'}); return; }
    const tUser = db.users[target];
    if (!tUser||!tUser.gameState) { send(res,404,{error:'Jogador nao encontrado.'}); return; }
    if (!onlineMap.has(target)) { send(res,400,{error:tUser.gameState.name+' nao esta online.'}); return; }
    // Cant be in another party
    const other = Object.values(db.parties).find(p => p.members.some(m => m.username === target));
    if (other) { send(res,409,{error:'Jogador ja esta em outra party.'}); return; }
    party.pendingInvites.push(target);
    saveDB(db);
    sendSSE(target, 'party_invite', { partyId: party.id, fromName: db.users[username].gameState.name });
    send(res,200,{ok:true});
    return;
  }

  if (method === 'POST' && url === '/api/party/accept') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { partyId } = await readBody(req);
    const db = loadDB();
    if (!db.parties||!db.parties[partyId]) { send(res,404,{error:'Party nao encontrada.'}); return; }
    const party = db.parties[partyId];
    const idx = party.pendingInvites.indexOf(username);
    if (idx < 0) { send(res,403,{error:'Voce nao foi convidado para esta party.'}); return; }
    if (party.members.length >= party.maxSize) { send(res,400,{error:'Party cheia.'}); return; }
    // Remove from any other party first
    Object.values(db.parties).forEach(p => {
      if (p.id !== partyId) p.members = p.members.filter(m => m.username !== username);
    });
    party.pendingInvites.splice(idx, 1);
    const u = db.users[username];
    party.members.push({ username, name: u.gameState.name, race: u.gameState.race, level: u.gameState.level });
    saveDB(db);
    // Notify all party members
    party.members.forEach(m => sendSSE(m.username, 'party_update', { party }));
    send(res,200,{ok:true, party});
    return;
  }

  if (method === 'POST' && url === '/api/party/decline') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { partyId } = await readBody(req);
    const db = loadDB();
    if (!db.parties||!db.parties[partyId]) { send(res,200,{ok:true}); return; }
    const party = db.parties[partyId];
    party.pendingInvites = party.pendingInvites.filter(u => u !== username);
    saveDB(db);
    sendSSE(party.leader, 'party_invite_declined', { username, name: db.users[username]?.gameState?.name||username });
    send(res,200,{ok:true});
    return;
  }

  if (method === 'POST' && url === '/api/party/leave') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const db = loadDB();
    if (!db.parties) db.parties = {};
    const party = Object.values(db.parties).find(p => p.members.some(m => m.username === username));
    if (!party) { send(res,200,{ok:true}); return; }
    party.members = party.members.filter(m => m.username !== username);
    if (party.leader === username || party.members.length === 0) {
      // Disband party
      party.members.forEach(m => sendSSE(m.username, 'party_disbanded', {}));
      delete db.parties[party.id];
    } else {
      party.members.forEach(m => sendSSE(m.username, 'party_update', { party }));
    }
    saveDB(db);
    send(res,200,{ok:true});
    return;
  }

  if (method === 'POST' && url === '/api/party/kick') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { targetUsername } = await readBody(req);
    const target = (targetUsername||'').toLowerCase();
    const db = loadDB();
    if (!db.parties) db.parties = {};
    const party = Object.values(db.parties).find(p => p.leader === username);
    if (!party) { send(res,403,{error:'Voce nao e lider de uma party.'}); return; }
    party.members = party.members.filter(m => m.username !== target);
    saveDB(db);
    sendSSE(target, 'party_kicked', {});
    party.members.forEach(m => sendSSE(m.username, 'party_update', { party }));
    send(res,200,{ok:true});
    return;
  }

  if (method === 'GET' && url === '/api/party/state') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const db = loadDB();
    if (!db.parties) db.parties = {};
    const party = Object.values(db.parties).find(p => p.members.some(m => m.username === username));
    send(res,200,{party: party||null});
    return;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // PARTY MISSION COMPLETE — Distribute XP and gold by table
  // Body: { missionId, totalXp, totalGold, droppedItemId? }
  // Server applies distribution and notifies all party members
  // ═══════════════════════════════════════════════════════════════════════
  if (method === 'POST' && url === '/api/party/distribute') {
    const username = verifyToken(getToken(req));
    if (!username) { send(res, 401, { error: 'Nao autenticado.' }); return; }
    const { totalXp, totalGold, missionName } = await readBody(req);
    const db = loadDB();
    if (!db.parties) db.parties = {};
    const party = Object.values(db.parties).find(p => p.members.some(m => m.username === username));
    if (!party) { send(res,404,{error:'Voce nao esta em uma party.'}); return; }
    if (party.leader !== username) { send(res,403,{error:'Apenas o lider distribui as recompensas.'}); return; }

    // Distribution percentages by party size — leader gets first slice
    const DIST_TABLE = {
      1: [100],
      2: [85, 15],
      3: [70, 15, 15],
      4: [55, 15, 15, 15],
      5: [120, 50, 50, 50, 50], // BONUS — total 320%
    };
    const size = party.members.length;
    const dist = DIST_TABLE[size] || [Math.floor(100/size)];

    const safeXp   = Math.max(0, Math.floor(totalXp||0));
    const safeGold = Math.max(0, Math.floor(totalGold||0));

    const distributions = [];
    party.members.forEach((m, i) => {
      const pct  = dist[i] || dist[dist.length-1];
      const xpShare   = Math.floor(safeXp   * pct / 100);
      const goldShare = Math.floor(safeGold * pct / 100);
      const tUser = db.users[m.username];
      if (!tUser||!tUser.gameState) return;
      const g = tUser.gameState;
      // Apply XP — let client handle level up via load
      g.xp = (g.xp||0) + xpShare;
      g.gold = (g.gold||0) + goldShare;
      g.stats = g.stats||{};
      g.stats.missions = (g.stats.missions||0) + 1;
      if (!g.log) g.log = [];
      g.log.unshift({msg:'🎉 Party "'+(missionName||'Missão')+'": +'+xpShare+' XP, +'+goldShare+' ouro ('+pct+'%)', cls:'good'});
      distributions.push({ username: m.username, name: m.name, pct, xp: xpShare, gold: goldShare });
      sendSSE(m.username, 'party_reward', { xp: xpShare, gold: goldShare, pct, missionName: missionName||'Missão' });
    });

    saveDB(db);
    send(res,200,{ok:true, distributions, partySize: size});
    return;
  }

  send(res, 404, { error: 'Endpoint nao encontrado.' });
}

const server = http.createServer(async (req, res) => {
  try { await handleRequest(req, res); }
  catch(e) { console.error('Erro:', e.message); try { send(res, 500, { error: 'Erro interno.' }); } catch(_) {} }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('\n  TERRAS DE ARATHORN - Servidor v2');
  console.log('  http://localhost:' + PORT);
  console.log('  PvP Duelos + Guerras de Cla + Jogadores Online');
  if (SECRET === 'arathorn_secret_key_2024_change_in_production') {
    console.warn('\n  AVISO: SECRET padrao em uso!');
    console.warn('  Para producao, edite a constante SECRET no inicio do server.js');
    console.warn('  Sem isso, tokens de autenticacao podem ser forjados.\n');
  } else {
    console.log('  Seguranca: SECRET personalizado OK');
  }

  // ── Initialize backup system ──
  console.log('\n[BACKUP] Sistema de backup automatico iniciado');
  startupBackupCheck();          // Check on startup
  scheduleMidnightBackup();      // Daily at midnight
  scheduleHourlyBackup();        // Emergency hourly (keeps only 7)
  console.log('[BACKUP] Pasta: ./backups/  |  Diarios: ' + MAX_DAILY_BACKUPS + '  |  Horarios: ' + MAX_HOURLY_BACKUPS + '\n');
});

// Graceful shutdown — backup before exit
process.on('SIGINT', () => {
  console.log('\n[BACKUP] Servidor parando — criando backup de emergencia...');
  makeBackup('shutdown');
  process.exit(0);
});
process.on('SIGTERM', () => {
  console.log('\n[BACKUP] SIGTERM recebido — criando backup...');
  makeBackup('shutdown');
  process.exit(0);
});
