/* Plinko — server-authoritative RGS (provably-fair, no deps) */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const E = require('./engine.js');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DEMO_START = E.CFG.DEMO_START;
const MAXWIN = E.CFG.MAX_WIN_X;
const BET_MIN = 0.10, BET_MAX = 100;

/* provably-fair RNG: resumable HMAC-SHA256 stream keyed by serverSeed/clientSeed/nonce */
function makeRng(serverSeed, clientSeed, nonce, startIndex) {
  let i = startIndex | 0;
  const fn = function () {
    const block = i >> 3, within = i & 7;   // 8 floats per 32-byte digest
    const h = crypto.createHmac('sha256', serverSeed).update(clientSeed + ':' + nonce + ':' + block).digest();
    i++;
    return h.readUInt32BE(within * 4) / 4294967296;
  };
  fn.index = () => i;
  return fn;
}

const sessions = new Map();
function newSession() {
  const token = crypto.randomBytes(24).toString('hex');
  const serverSeed = crypto.randomBytes(32).toString('hex');
  const serverSeedHash = crypto.createHash('sha256').update(serverSeed).digest('hex');
  const clientSeed = crypto.randomBytes(8).toString('hex');
  const s = { token, serverSeed, serverSeedHash, clientSeed, nonce: 0, balance: DEMO_START };
  sessions.set(token, s);
  return s;
}
function round2(v){ return Math.round(v*100)/100; }

/* ---- API ---- */
function api(req, res, body) {
  const url = req.url.split('?')[0];
  const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(obj)); };
  let d = {}; try { d = body ? JSON.parse(body) : {}; } catch (e) { return send(400, { error: 'bad json' }); }

  if (url === '/api/session') {
    const s = newSession();
    return send(200, {
      token: s.token, balance: s.balance,
      serverSeedHash: s.serverSeedHash, clientSeed: s.clientSeed, nonce: s.nonce,
      currency: 'USD',
      config: {
        rowsMin: E.CFG.ROWS_MIN, rowsMax: E.CFG.ROWS_MAX, risks: E.CFG.RISKS,
        maxWinX: MAXWIN, betMin: BET_MIN, betMax: BET_MAX, tables: E.TABLES
      }
    });
  }
  const s = sessions.get(d.token);
  if (!s) return send(401, { error: 'no session' });

  if (url === '/api/drop') {
    const bet = round2(+d.bet);
    const rows = d.rows | 0;
    const risk = String(d.risk || '');
    if (!(bet >= BET_MIN - 1e-9 && bet <= BET_MAX + 1e-9)) return send(400, { error: 'bad bet' });
    if (!E.validRows(rows)) return send(400, { error: 'bad rows' });
    if (!E.validRisk(risk)) return send(400, { error: 'bad risk' });
    if (s.balance < bet - 1e-9) return send(200, { error: 'insufficient', balance: s.balance });

    s.balance = round2(s.balance - bet);
    s.nonce++;
    const rng = makeRng(s.serverSeed, s.clientSeed, s.nonce, 0);
    const r = E.play({ bet, rows, risk, rng });
    const capped = r.win > bet * MAXWIN;
    const win = round2(capped ? bet * MAXWIN : r.win);
    s.balance = round2(s.balance + win);

    return send(200, {
      path: r.path, bucket: r.bucket, mult: r.mult, win, capped,
      bet, rows, risk, balance: s.balance, roundId: s.nonce, nonce: s.nonce
    });
  }

  if (url === '/api/reveal') {   // provably-fair: reveal + rotate seed
    const old = { serverSeed: s.serverSeed, serverSeedHash: s.serverSeedHash, clientSeed: s.clientSeed, nonceUsed: s.nonce };
    s.serverSeed = crypto.randomBytes(32).toString('hex');
    s.serverSeedHash = crypto.createHash('sha256').update(s.serverSeed).digest('hex');
    s.nonce = 0;
    return send(200, { revealed: old, newServerSeedHash: s.serverSeedHash, clientSeed: s.clientSeed });
  }
  return send(404, { error: 'unknown endpoint' });
}

/* ---- static + router ---- */
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.mp3': 'audio/mpeg', '.webp': 'image/webp', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webm': 'video/webm' };
http.createServer((req, res) => {
  if (req.url.startsWith('/api/')) {
    if (req.method !== 'POST') { res.writeHead(405).end('Method Not Allowed'); return; }
    let body = ''; req.on('data', c => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => { try { api(req, res, body); } catch (e) { res.writeHead(500, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'server', detail: '' + (e && e.message) })); } });
    return;
  }
  let p = decodeURIComponent(req.url.split('?')[0]);
  if (p === '/' || p === '') p = '/index.html';
  const file = path.join(ROOT, path.normalize(p).replace(/^(\.\.[/\\])+/, ''));
  if (!file.startsWith(ROOT)) { res.writeHead(403).end('Forbidden'); return; }
  fs.readFile(file, (err, data) => {
    if (err) { fs.readFile(path.join(ROOT, 'index.html'), (e2, idx) => { if (e2) { res.writeHead(404).end('Not found'); return; } res.writeHead(200, { 'Content-Type': TYPES['.html'] }).end(idx); }); return; }
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, { 'Content-Type': TYPES[ext] || 'application/octet-stream', 'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=86400' }).end(data);
  });
}).listen(PORT, () => console.log('Plinko RGS listening on ' + PORT));
