/* UKI CHAT – anonymer Messenger (Testversion)
 *
 * Aufbau:
 *  - UI, Passwort-Sperre und die gesamte Ende-zu-Ende-Verschlüsselung laufen hier in JavaScript (WebCrypto).
 *  - Der Transport läuft in der Android-App über das Tor-Netz (natives Plugin "TorChat").
 *    Im normalen Browser gibt es nur einen Test-Transport zwischen zwei Tabs (BroadcastChannel).
 *  - Nichts wird dauerhaft gespeichert außer dem Passwort-Prüfwert und dem Fehlversuchszähler.
 */
'use strict';

const CFG = {
  MESSAGE_TTL_MS: 60 * 60 * 1000,      // jede Nachricht lebt höchstens 60 Minuten
  QR_TTL_MS: 10 * 60 * 1000,           // ein angezeigter Code gilt 10 Minuten
  MAX_FILE_BYTES: 15 * 1024 * 1024,    // 15 MB pro Datei
  FRAME_BYTES: 192 * 1024,             // Größe der Übertragungsstücke
  LOGIN_ITER: 600000,                  // PBKDF2-Runden für das App-Passwort
  CHANNEL_ITER: 300000,                // PBKDF2-Runden für das Kanal-Passwort
  MAX_ATTEMPTS: 3,
  AUTOLOCK_MS: 2 * 60 * 1000,          // nach 2 Minuten im Hintergrund wieder sperren
  MAX_SKIP: 200,
};

const LS_HASH = 'siegel.pw';
const LS_FAILS = 'siegel.fails';

// ---------------------------------------------------------------- Hilfsfunktionen
const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();
const subtle = crypto.subtle;

function b64(bytes) {
  bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
function concat(...arrs) {
  const len = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
function rand(n) { return crypto.getRandomValues(new Uint8Array(n)); }
function randId() { return b64(rand(9)).replace(/[+/=]/g, 'x'); }
function u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; }
function readU32(b, o) { return new DataView(b.buffer, b.byteOffset).getUint32(o); }
function wipeBytes(b) { if (b && b.fill) b.fill(0); }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

let toastTimer = null;
function toast(text, ms = 2600) {
  const t = $('toast');
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, ms);
}

// ---------------------------------------------------------------- Bildschirme
let currentScreen = null;
const backStack = [];
function show(id, { push = true } = {}) {
  if (currentScreen && push) backStack.push(currentScreen);
  document.querySelectorAll('.screen').forEach((s) => { s.hidden = s.id !== id; });
  currentScreen = id;
}
function goMenu() { backStack.length = 0; show('screen-menu', { push: false }); }

// ---------------------------------------------------------------- Passwort und Sperre
function validatePassword(pw) {
  if (/[0-9]/.test(pw)) return 'Bitte keine Zahlen verwenden, nur Wörter.';
  const words = pw.trim().split(/\s+/).filter((w) => w.length >= 2);
  if (words.length < 4) return 'Bitte mindestens 4 Wörter verwenden.';
  if (pw.trim().length < 20) return 'Bitte mindestens 20 Zeichen verwenden.';
  return null;
}

async function pbkdf2(pw, salt, iter, bits = 256) {
  const key = await subtle.importKey('raw', enc.encode(pw.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, key, bits));
}

function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* ignore */ } }

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

async function setupPassword() {
  const p1 = $('setup-pw1').value;
  const p2 = $('setup-pw2').value;
  const err = $('setup-error');
  const problem = validatePassword(p1);
  if (problem) { err.textContent = problem; err.hidden = false; return; }
  if (p1 !== p2) { err.textContent = 'Die Passwörter stimmen nicht überein.'; err.hidden = false; return; }
  err.hidden = true;
  $('setup-btn').disabled = true;
  $('setup-btn').textContent = 'Wird gesichert …';
  const salt = rand(16);
  const hash = await pbkdf2(p1, salt, CFG.LOGIN_ITER);
  lsSet(LS_HASH, JSON.stringify({ s: b64(salt), h: b64(hash), i: CFG.LOGIN_ITER }));
  lsSet(LS_FAILS, '0');
  $('setup-pw1').value = ''; $('setup-pw2').value = '';
  $('setup-btn').disabled = false;
  $('setup-btn').textContent = 'Passwort festlegen';
  unlocked();
}

async function tryUnlock() {
  const pw = $('lock-pw').value;
  const err = $('lock-error');
  if (!pw) return;
  let rec;
  try { rec = JSON.parse(lsGet(LS_HASH)); } catch (e) { rec = null; }
  if (!rec) { await wipeEverything(); return; }
  // Den Versuch ZUERST zählen: Wer die App während der Prüfung abwürgt, bekommt keinen Gratis-Versuch.
  const fails = (parseInt(lsGet(LS_FAILS) || '0', 10) || 0) + 1;
  lsSet(LS_FAILS, String(fails));
  if (lsGet(LS_FAILS) !== String(fails)) { await wipeEverything(); return; }
  $('lock-btn').disabled = true;
  const hash = await pbkdf2(pw, unb64(rec.s), rec.i);
  $('lock-btn').disabled = false;
  $('lock-pw').value = '';
  if (timingSafeEqual(hash, unb64(rec.h))) {
    lsSet(LS_FAILS, '0');
    err.hidden = true;
    unlocked();
    return;
  }
  if (fails >= CFG.MAX_ATTEMPTS) {
    await wipeEverything();
    toast('3 falsche Versuche: Die App wurde vollständig zurückgesetzt.', 5000);
    return;
  }
  const left = CFG.MAX_ATTEMPTS - fails;
  err.textContent = `Falsches Passwort. Noch ${left} ${left === 1 ? 'Versuch' : 'Versuche'}, danach wird alles gelöscht.`;
  err.hidden = false;
}

let isUnlocked = false;
function unlocked() {
  isUnlocked = true;
  unlockAudio();
  if (channel && channel.state !== 'closed' && channel.keys) show('screen-chat', { push: false });
  else goMenu();
}

function lockApp() {
  isUnlocked = false;
  backStack.length = 0;
  stopScanner();
  show('screen-lock', { push: false });
}

async function wipeEverything() {
  await leaveChannel({ notify: true, silent: true });
  try { localStorage.clear(); } catch (e) { /* ignore */ }
  try { sessionStorage.clear(); } catch (e) { /* ignore */ }
  try {
    if (indexedDB.databases) {
      const dbs = await indexedDB.databases();
      for (const d of dbs) if (d.name) indexedDB.deleteDatabase(d.name);
    }
  } catch (e) { /* ignore */ }
  try { if (window.caches) for (const k of await caches.keys()) await caches.delete(k); } catch (e) { /* ignore */ }
  try { await transport.shutdown(); } catch (e) { /* ignore */ }
  if (native) { try { await native.wipe(); } catch (e) { /* ignore */ } }
  isUnlocked = false;
  backStack.length = 0;
  show('screen-setup', { push: false });
}

// Automatisch sperren, wenn die App länger im Hintergrund war
let hiddenAt = 0;
document.addEventListener('visibilitychange', () => {
  if (document.hidden) { hiddenAt = Date.now(); stopScanner(); return; }
  if (isUnlocked && hiddenAt && Date.now() - hiddenAt > CFG.AUTOLOCK_MS) lockApp();
  hiddenAt = 0;
});

// ---------------------------------------------------------------- Ton
let audioCtx = null;
function unlockAudio() {
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    if (audioCtx.state === 'suspended') audioCtx.resume();
  } catch (e) { audioCtx = null; }
}
function beep() {
  if (native && document.hidden) return; // im Hintergrund spielt die Android-App den Systemton
  if (!audioCtx) return;
  const t0 = audioCtx.currentTime;
  [880, 1320].forEach((f, i) => {
    const o = audioCtx.createOscillator();
    const g = audioCtx.createGain();
    o.frequency.value = f;
    g.gain.setValueAtTime(0.0001, t0 + i * 0.12);
    g.gain.exponentialRampToValueAtTime(0.18, t0 + i * 0.12 + 0.02);
    g.gain.exponentialRampToValueAtTime(0.0001, t0 + i * 0.12 + 0.11);
    o.connect(g).connect(audioCtx.destination);
    o.start(t0 + i * 0.12);
    o.stop(t0 + i * 0.12 + 0.12);
  });
}

// ---------------------------------------------------------------- Transport
// Android: natives Tor-Plugin. Browser: Test-Transport zwischen zwei Tabs.
const isNative = !!(window.Capacitor && window.Capacitor.isNativePlatform && window.Capacitor.isNativePlatform());
const native = isNative ? window.Capacitor.registerPlugin('TorChat') : null;
const AppPlugin = isNative ? window.Capacitor.registerPlugin('App') : null;

// Jede Verbindung hat eine Nummer (conn). Erst wenn über eine Verbindung ein gültig verschlüsseltes
// Paket ankommt, wird sie zur aktiven Verbindung; alle anderen werden geschlossen. So kann ein Fremder,
// der die Tor-Adresse kennt, den Kanal weder übernehmen noch stören.
function makeNativeTransport() {
  const handlers = { data: () => {}, state: () => {}, progress: () => {} };
  let started = null;
  native.addListener('data', (ev) => handlers.data(unb64(ev.data), ev.conn));
  native.addListener('state', (ev) => handlers.state(ev.state, ev.conn));
  native.addListener('progress', (ev) => handlers.progress(ev.progress, ev.summary || ''));
  return {
    name: 'tor',
    onData(cb) { handlers.data = cb; },
    onState(cb) { handlers.state = cb; },
    onProgress(cb) { handlers.progress = cb; },
    async init() {
      if (!started) started = native.start().then((r) => r.address).catch((e) => { started = null; throw e; });
      return started;
    },
    async listen() { await native.listen(); },
    async connect(addr) { await native.connect({ address: addr }); },
    async send(bytes, notify, conn) { await native.send({ data: b64(bytes), notify: !!notify, conn }); },
    async promote(conn) { await native.promote({ conn }); },
    async drop(conn) { await native.drop({ conn }); },
    async close() { await native.closeConnection(); },
    async shutdown() { started = null; await native.stop(); },
  };
}

function makeLoopbackTransport() {
  const handlers = { data: () => {}, state: () => {}, progress: () => {} };
  const bc = ('BroadcastChannel' in window) ? new BroadcastChannel('siegel-dev') : null;
  let me = null;
  const conns = new Map(); // conn -> Adresse der Gegenseite
  let nextId = 1;
  const idFor = (addr) => { for (const [id, a] of conns) if (a === addr) return id; return null; };
  if (bc) {
    bc.onmessage = (ev) => {
      const m = ev.data;
      if (!me || !m || m.to !== me) return;
      if (m.t === 'hello') {
        const id = nextId++; conns.set(id, m.from);
        bc.postMessage({ t: 'welcome', to: m.from, from: me });
        handlers.state('connected', id);
      } else if (m.t === 'welcome') {
        const id = idFor(m.from);
        if (id) handlers.state('connected', id);
      } else if (m.t === 'data') {
        const id = idFor(m.from);
        if (id) handlers.data(new Uint8Array(m.d), id);
      } else if (m.t === 'bye') {
        const id = idFor(m.from);
        if (id) { conns.delete(id); handlers.state('disconnected', id); }
      }
    };
  }
  return {
    name: 'loopback',
    onData(cb) { handlers.data = cb; },
    onState(cb) { handlers.state = cb; },
    onProgress(cb) { handlers.progress = cb; },
    async init() {
      if (!bc) throw new Error('Dieser Browser kann den Testmodus nicht.');
      if (!me) { handlers.progress(100, 'Testmodus'); me = 'test' + randId().toLowerCase() + '.local'; }
      return me;
    },
    async listen() {},
    async connect(addr) { const id = nextId++; conns.set(id, addr); bc.postMessage({ t: 'hello', to: addr, from: me }); },
    async send(bytes, notify, conn) {
      const to = conns.get(conn);
      if (!to) throw new Error('nicht verbunden');
      bc.postMessage({ t: 'data', to, from: me, d: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) });
    },
    async promote(conn) { for (const [id, a] of [...conns]) if (id !== conn) { bc.postMessage({ t: 'bye', to: a, from: me }); conns.delete(id); } },
    async drop(conn) { const a = conns.get(conn); if (a) { bc.postMessage({ t: 'bye', to: a, from: me }); conns.delete(conn); } },
    async close() { for (const a of conns.values()) bc.postMessage({ t: 'bye', to: a, from: me }); conns.clear(); },
    async shutdown() { await this.close(); me = null; },
  };
}

const transport = native ? makeNativeTransport() : makeLoopbackTransport();

// ---------------------------------------------------------------- Kryptografie des Kanals
/*
 * Schlüsselaufbau:
 *  - Jede Seite erzeugt pro Kanal ein neues ECDH-Schlüsselpaar (P-256). Der öffentliche Teil steht im QR-Code.
 *  - Gemeinsames Geheimnis = ECDH  +  PBKDF2(Kanal-Passwort). Ohne das Passwort entsteht ein anderer Schlüssel.
 *  - Daraus per HKDF zwei Kettenschlüssel (je Richtung).
 *  - Pro Nachricht: Nachrichtenschlüssel = HMAC(Kette, 1), neue Kette = HMAC(Kette, 2). Alte Schlüssel werden verworfen.
 *  - Verschlüsselung: AES-256-GCM mit Zähler als Zusatzdaten.
 */
async function hmac(keyBytes, data) {
  const k = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}
async function sha256(data) { return new Uint8Array(await subtle.digest('SHA-256', data)); }

async function newKeyPair() {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  return { priv: kp.privateKey, pub };
}

async function deriveChannelKeys(myPriv, myPub, theirPub, channelPw, iAmA) {
  const theirKey = await subtle.importKey('raw', theirPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: theirKey }, myPriv, 256));
  const pubA = iAmA ? myPub : theirPub;
  const pubB = iAmA ? theirPub : myPub;
  const transcript = await sha256(concat(enc.encode('siegel-v1'), pubA, pubB));
  const pwKey = await pbkdf2(channelPw, transcript, CFG.CHANNEL_ITER);
  const ikm = await subtle.importKey('raw', concat(shared, pwKey), 'HKDF', false, ['deriveBits']);
  const okm = new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: transcript, info: enc.encode('siegel-chains') }, ikm, 512));
  wipeBytes(shared); wipeBytes(pwKey);
  const chainAB = okm.slice(0, 32);
  const chainBA = okm.slice(32, 64);
  wipeBytes(okm);
  return {
    send: { chain: iAmA ? chainAB : chainBA, n: 0 },
    recv: { chain: iAmA ? chainBA : chainAB, n: 0, skipped: new Map() },
    fingerprint: fingerprintSymbols(await sha256(concat(enc.encode('siegel-fp'), pubA, pubB))),
  };
}

const FP_SYMBOLS = ['🍎','🍋','🍇','🍒','🥝','🌽','🥕','🍄','🌵','🌲','🌻','🌙','⭐','🔥','💧','❄️','⚡','🌈','🐶','🐱','🦊','🐻','🐼','🐸','🐙','🦋','🐝','🐢','🦉','🐳','🚀','⚓','🎈','🎸','🎲','🔑','💎','🔔','📌','🧭','⛵','🏠','🗻','🧩','🎯','🪁','🧲','🌀'];
function fingerprintSymbols(hash) {
  const out = [];
  for (let i = 0; i < 6; i++) out.push(FP_SYMBOLS[hash[i] % FP_SYMBOLS.length]);
  return out.join(' ');
}

async function ratchetStep(chain) {
  const mk = await hmac(chain, new Uint8Array([1]));
  const next = await hmac(chain, new Uint8Array([2]));
  return { mk, next };
}

async function encryptPayload(keys, plain) {
  const n = keys.send.n;
  const { mk, next } = await ratchetStep(keys.send.chain);
  wipeBytes(keys.send.chain);
  keys.send.chain = next;
  keys.send.n = n + 1;
  const iv = rand(12);
  const k = await subtle.importKey('raw', mk, 'AES-GCM', false, ['encrypt']);
  wipeBytes(mk);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: u32(n) }, k, plain));
  return concat(u32(n), iv, ct);
}

async function decryptPayload(keys, packet) {
  const n = readU32(packet, 0);
  const iv = packet.subarray(4, 16);
  const ct = packet.subarray(16);
  const r = keys.recv;
  let mk;
  if (n < r.n) {
    mk = r.skipped.get(n);
    if (!mk) throw new Error('replay');
    r.skipped.delete(n);
  } else {
    if (n - r.n > CFG.MAX_SKIP) throw new Error('too far');
    let chain = r.chain;
    let i = r.n;
    const newSkipped = [];
    while (i < n) {
      const s = await ratchetStep(chain);
      newSkipped.push([i, s.mk]);
      chain = s.next; i++;
    }
    const s = await ratchetStep(chain);
    // Erst nach erfolgreicher Entschlüsselung übernehmen
    const k = await subtle.importKey('raw', s.mk, 'AES-GCM', false, ['decrypt']);
    const plain = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: u32(n) }, k, ct));
    wipeBytes(s.mk);
    for (const [j, key] of newSkipped) r.skipped.set(j, key);
    while (r.skipped.size > CFG.MAX_SKIP) { const first = r.skipped.keys().next().value; wipeBytes(r.skipped.get(first)); r.skipped.delete(first); }
    r.chain = s.next; r.n = n + 1;
    return plain;
  }
  const k = await subtle.importKey('raw', mk, 'AES-GCM', false, ['decrypt']);
  wipeBytes(mk);
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: u32(n) }, k, ct));
}

// ---------------------------------------------------------------- Kanal
/*
 * Ablauf:
 *  A: "Mein Code"  -> Kanal-Passwort -> zeigt Code A (Tor-Adresse A + Schlüssel A)
 *  B: "Code scannen" -> Kanal-Passwort -> scannt Code A -> zeigt Code B und wartet
 *  A: scannt Code B -> verbindet sich über Tor mit B
 */
let channel = null;

function newChannel(role, channelPw) {
  return {
    role,                 // 'A' oder 'B'
    pw: channelPw,
    kp: null,
    myAddr: null,
    peerAddr: null,
    keys: null,
    state: 'setup',       // setup -> connecting -> open -> closed
    verified: false,
    messages: [],         // {id, el, expires, urls:[]}
    outbox: new Map(),    // id -> payload-Objekt (bis zur Bestätigung)
    seen: new Set(),
    rx: new Map(),        // laufender Empfang großer Pakete je Verbindung
    pending: new Map(),   // Verbindungen, die sich noch nicht ausgewiesen haben
    active: null,         // bestätigte Verbindung zum Partner
    lastRx: 0,
    warned: false,
    reconnectTimer: null,
    createdAt: Date.now(),
  };
}

async function startChannelFlow(role) {
  show('screen-chpw');
  $('chpw').value = '';
  $('chpw-error').hidden = true;
  $('chpw-btn').onclick = async () => {
    const pw = $('chpw').value;
    if (pw.trim().length < 6) { $('chpw-error').textContent = 'Bitte mindestens 6 Zeichen.'; $('chpw-error').hidden = false; return; }
    $('chpw').value = '';
    await leaveChannel({ notify: true, silent: true });
    channel = newChannel(role, pw);
    channel.kp = await newKeyPair();
    if (role === 'A') showMyCode('Mein Code', 'Lass deinen Partner diesen Code scannen. Danach scannst du seinen Code.');
    else startScan('Code des Partners scannen');
  };
}

function qrPayload() {
  return JSON.stringify({ s: 1, r: channel.role, a: channel.myAddr, k: b64(channel.kp.pub), t: Date.now() });
}

function renderQr(text) {
  const qr = qrcode(0, 'M');
  qr.addData(text, 'Byte');
  qr.make();
  const n = qr.getModuleCount();
  const quiet = 2;
  let path = '';
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) path += `M${c + quiet},${r + quiet}h1v1h-1z`;
  const size = n + quiet * 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges"><rect width="${size}" height="${size}" fill="#fff"/><path d="${path}" fill="#000"/></svg>`;
}

let torReady = false;
transport.onProgress((p, summary) => {
  torReady = p >= 100;
  const st = $('show-status');
  if (st && currentScreen === 'screen-show' && !torReady) st.textContent = `Anonyme Verbindung wird aufgebaut … ${p} %`;
});

async function ensureAddress() {
  if (channel.myAddr) return channel.myAddr;
  channel.myAddr = await transport.init();
  await transport.listen();
  return channel.myAddr;
}

async function showMyCode(title, hint) {
  show('screen-show');
  $('show-title').textContent = title;
  $('show-hint').textContent = hint;
  $('qr-box').innerHTML = '';
  $('show-next').hidden = true;
  $('show-status').textContent = 'Anonyme Verbindung wird aufgebaut …';
  const ch = channel;
  try {
    await ensureAddress();
  } catch (e) {
    $('show-status').textContent = 'Tor konnte nicht starten: ' + (e && e.message ? e.message : e);
    return;
  }
  if (channel !== ch) return;
  $('qr-box').innerHTML = renderQr(qrPayload());
  if (ch.role === 'A') {
    $('show-status').textContent = 'Code ist 10 Minuten gültig.';
    $('show-next').hidden = false;
    $('show-next').onclick = () => startScan('Code des Partners scannen');
  } else {
    $('show-status').textContent = 'Warte, bis dein Partner diesen Code scannt …';
  }
  setTimeout(() => {
    if (channel === ch && ch.state === 'setup' && currentScreen === 'screen-show') {
      $('qr-box').innerHTML = '';
      $('show-status').textContent = 'Der Code ist abgelaufen. Bitte neu beginnen.';
      $('show-next').hidden = true;
    }
  }, CFG.QR_TTL_MS);
}

async function onScanned(text) {
  let d;
  try { d = JSON.parse(text); } catch (e) { d = null; }
  if (!d || d.s !== 1 || !d.a || !d.k || !d.r) { toast('Das ist kein gültiger Code dieser App.'); return false; }
  if (Date.now() - d.t > CFG.QR_TTL_MS + 60000) { toast('Dieser Code ist abgelaufen.'); return false; }
  const ch = channel;
  if (!ch) return false;
  if (d.r === ch.role) { toast(ch.role === 'A' ? 'Bitte den Code deines Partners scannen, nicht deinen eigenen Kanal-Code.' : 'Dein Partner muss zuerst "Mein Code" öffnen.'); return false; }
  let theirPub;
  try { theirPub = unb64(d.k); } catch (e) { toast('Ungültiger Code.'); return false; }
  if (theirPub.length !== 65) { toast('Ungültiger Code.'); return false; }
  ch.peerAddr = d.a;
  try {
    if (ch.role === 'B') await ensureAddress();
    ch.keys = await deriveChannelKeys(ch.kp.priv, ch.kp.pub, theirPub, ch.pw, ch.role === 'A');
  } catch (e) {
    toast('Fehler: ' + (e && e.message ? e.message : e));
    return false;
  }
  ch.pw = null; // Kanal-Passwort wird nicht mehr gebraucht
  if (ch.role === 'B') {
    showMyCode('Dein Code', 'Jetzt scannt dein Partner diesen Code.');
  } else {
    openChat();
    connectToPeer();
  }
  return true;
}

function connectToPeer() {
  const ch = channel;
  if (!ch || ch.state === 'closed' || ch.role !== 'A' || ch.active) return;
  setChatState('verbinde …', true);
  transport.connect(ch.peerAddr).catch(() => scheduleReconnect());
}
function scheduleReconnect() {
  const ch = channel;
  if (!ch || ch.state === 'closed' || ch.role !== 'A') return;
  clearTimeout(ch.reconnectTimer);
  ch.reconnectTimer = setTimeout(connectToPeer, 8000);
}

transport.onState((state, conn) => {
  const ch = channel;
  if (!ch || ch.state === 'closed' || !ch.keys) return;
  if (state === 'connected') {
    // Noch nicht vertrauenswürdig: Hallo schicken und auf ein gültiges Paket der Gegenseite warten.
    ch.pending.set(conn, { fails: 0, since: Date.now() });
    enqueue({ head: { type: 'hello', id: randId() }, body: null, notify: false, conn });
    setTimeout(() => {
      if (channel === ch && ch.pending.has(conn)) { ch.pending.delete(conn); transport.drop(conn).catch(() => {}); }
    }, 60000);
  } else if (state === 'disconnected') {
    ch.pending.delete(conn);
    ch.rx.delete(conn);
    if (ch.active === conn) {
      ch.active = null;
      setChatState('getrennt, verbinde neu …', true);
      scheduleReconnect();
    }
  }
});

// ---------------------------------------------------------------- Übertragung (Rahmen)
// Rahmen: [typ 1 Byte][...]. typ 0 = ganzes Paket, 1 = Anfang (Gesamtlänge 4 Byte), 2 = Fortsetzung
async function sendPacket(packet, notify, conn) {
  const F = CFG.FRAME_BYTES;
  if (packet.length <= F) { await transport.send(concat(new Uint8Array([0]), packet), notify, conn); return; }
  await transport.send(concat(new Uint8Array([1]), u32(packet.length), packet.subarray(0, F)), false, conn);
  for (let o = F; o < packet.length; o += F) {
    const last = o + F >= packet.length;
    await transport.send(concat(new Uint8Array([2]), packet.subarray(o, o + F)), last && notify, conn);
  }
}

// Empfang strikt nacheinander, damit die Schlüsselkette nie durcheinanderkommt.
let rxChain = Promise.resolve();
transport.onData((frame, conn) => {
  rxChain = rxChain.then(() => onFrame(frame, conn)).catch(() => {});
});

async function onFrame(frame, conn) {
  const ch = channel;
  if (!ch || !ch.keys || frame.length < 1) return;
  if (ch.active && conn !== ch.active && !ch.pending.has(conn)) return;
  // Noch nicht ausgewiesene Verbindungen dürfen nur kleine Einzelpakete schicken (Schutz vor Speicher-Flutung).
  if (conn !== ch.active && (frame[0] !== 0 || frame.length > 8192)) return rejectFrom(conn);
  let st = ch.rx.get(conn);
  const t = frame[0];
  if (t === 0) return handlePacket(frame.subarray(1), conn);
  if (t === 1 && frame.length >= 5) {
    const total = readU32(frame, 1);
    if (total > CFG.MAX_FILE_BYTES + 65536) { ch.rx.delete(conn); return rejectFrom(conn); }
    st = { buf: new Uint8Array(total), off: 0 };
    ch.rx.set(conn, st);
    const part = frame.subarray(5);
    if (part.length > total) { ch.rx.delete(conn); return rejectFrom(conn); }
    st.buf.set(part, 0); st.off = part.length;
    return;
  }
  if (t === 2 && st) {
    const part = frame.subarray(1);
    if (st.off + part.length > st.buf.length) { ch.rx.delete(conn); return rejectFrom(conn); }
    st.buf.set(part, st.off); st.off += part.length;
    if (st.off === st.buf.length) { ch.rx.delete(conn); return handlePacket(st.buf, conn); }
    return;
  }
  return rejectFrom(conn);
}

// Ungültige Daten: Verbindung nach 3 Fehlern trennen. Der Kanal selbst bleibt bestehen.
function rejectFrom(conn) {
  const ch = channel;
  if (!ch) return;
  const p = ch.pending.get(conn);
  if (p) {
    p.fails++;
    if (!ch.verified && !ch.warned) {
      ch.warned = true;
      const txt = 'Verbindung abgelehnt: Das Kanal-Passwort ist bei euch verschieden, oder ein Fremder versucht sich einzuklinken. Bitte zurück und neu beginnen.';
      if (currentScreen === 'screen-show') $('show-status').textContent = txt;
      $('chat-banner').hidden = false;
      $('chat-banner').textContent = txt;
    }
    if (p.fails >= 3) {
      ch.pending.delete(conn);
      transport.drop(conn).catch(() => {});
    }
  }
}

// Nutzlast: [Kopf-Länge 4 Byte][Kopf JSON][Datei-Bytes]
function encodePayload(head, body) {
  const h = enc.encode(JSON.stringify(head));
  return concat(u32(h.length), h, body || new Uint8Array(0));
}
function decodePayload(plain) {
  const hl = readU32(plain, 0);
  if (hl > plain.length - 4 || hl > 65536) throw new Error('Kopf');
  const head = JSON.parse(dec.decode(plain.subarray(4, 4 + hl)));
  if (!head || typeof head !== 'object' || typeof head.type !== 'string') throw new Error('Kopf');
  return { head, body: plain.subarray(4 + hl) };
}

// Senden strikt nacheinander (gleicher Grund wie beim Empfang).
const sendQueue = [];
let sending = false;
let sendIdle = Promise.resolve();
let sendIdleResolve = null;
function enqueue(job) {
  sendQueue.push(job);
  pumpQueue();
}
async function pumpQueue() {
  if (sending) return;
  sending = true;
  sendIdle = new Promise((r) => { sendIdleResolve = r; });
  try {
    while (sendQueue.length) {
      const job = sendQueue.shift();
      const ch = channel;
      if (!ch || !ch.keys || ch.state === 'closed') continue;
      const conn = job.conn || ch.active;
      if (!conn) continue; // nicht verbunden: bleibt im Postausgang und wird später erneut gesendet
      try {
        const packet = await encryptPayload(ch.keys, encodePayload(job.head, job.body));
        await sendPacket(packet, job.notify, conn);
      } catch (e) { /* bei Verbindungsabbruch wird später erneut gesendet */ }
    }
  } finally { sending = false; if (sendIdleResolve) sendIdleResolve(); }
}
function sendPayload(p, track = true) {
  if (track && channel) channel.outbox.set(p.head.id, p);
  enqueue(p);
}
function sendControl(head) {
  enqueue({ head: { id: randId(), ...head }, body: null, notify: false });
}

async function handlePacket(packet, conn) {
  const ch = channel;
  if (!ch || !ch.keys || packet.length < 17) return rejectFrom(conn);
  let plain;
  try { plain = await decryptPayload(ch.keys, packet); } catch (e) { return rejectFrom(conn); }
  let msg;
  try { msg = decodePayload(plain); } catch (e) { return rejectFrom(conn); }
  const { head, body } = msg;
  // Gültig verschlüsselt: diese Verbindung gehört zum echten Partner.
  if (ch.active !== conn) {
    if (ch.state !== 'open') openChat();
    ch.active = conn;
    ch.pending.delete(conn);
    transport.promote(conn).catch(() => {});
    clearTimeout(ch.reconnectTimer);
    setChatState('verbunden', false);
    // Unbestätigte Nachrichten erneut senden
    for (const p of ch.outbox.values()) enqueue(p);
  }
  ch.lastRx = Date.now();
  if (!ch.verified) {
    ch.verified = true;
    if (ch.warned) $('chat-banner').textContent = 'Vergleicht die Symbole oben. Sind sie bei euch beiden gleich, hört niemand mit.';
  }
  switch (head.type) {
    case 'hello': case 'ping': return;
    case 'ack': ch.outbox.delete(head.id); markDelivered(head.id); return;
    case 'bye':
      await leaveChannel({ notify: false });
      toast('Dein Partner hat den Kanal verlassen. Alles wurde gelöscht.', 4000);
      return;
    case 'text': case 'image': case 'audio': case 'file':
      if (typeof head.id !== 'string' || head.id.length > 40) return;
      if (head.type === 'text' && (typeof head.text !== 'string' || head.text.length > 20000)) return;
      sendControl({ type: 'ack', id: head.id });
      if (ch.seen.has(head.id)) return;
      ch.seen.add(head.id);
      renderMessage({ ...head, mine: false }, body);
      beep();
      return;
    default:
  }
}

// Lebenszeichen: alle 20 Sekunden. Kommt 70 Sekunden lang nichts, wird neu verbunden.
setInterval(() => {
  const ch = channel;
  if (!ch || !ch.keys || !ch.active || ch.state === 'closed') return;
  sendControl({ type: 'ping' });
  if (ch.lastRx && Date.now() - ch.lastRx > 70000) {
    const dead = ch.active;
    ch.active = null;
    transport.drop(dead).catch(() => {});
    setChatState('getrennt, verbinde neu …', true);
    scheduleReconnect();
  }
}, 20000);

// ---------------------------------------------------------------- Chat-Oberfläche
function setChatState(text, warn) {
  const s = $('chat-state');
  s.textContent = text;
  s.classList.toggle('warn', !!warn);
}

function openChat() {
  const ch = channel;
  ch.state = 'open';
  $('messages').innerHTML = '';
  $('chat-fp').textContent = ch.keys ? ch.keys.fingerprint : '';
  $('chat-banner').hidden = false;
  $('chat-banner').textContent = 'Vergleicht die Symbole oben. Sind sie bei euch beiden gleich, hört niemand mit.';
  backStack.length = 0;
  show('screen-chat', { push: false });
  addSys('Kanal geöffnet. Nachrichten werden nach spätestens 60 Minuten gelöscht.');
  setChatState(ch.role === 'A' ? 'verbinde …' : 'warte …', true);
}

function addSys(text) {
  const el = document.createElement('div');
  el.className = 'msg sys';
  el.textContent = text;
  $('messages').appendChild(el);
  scrollDown();
}

function scrollDown() { const m = $('messages'); m.scrollTop = m.scrollHeight; }

function fmtTime(ts) { const d = new Date(ts); return d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }); }

const EMOJI_ONLY = /^(\p{Extended_Pictographic}|\p{Emoji_Component}|‍|️|\s){1,12}$/u;

function renderMessage(m, body) {
  const ch = channel;
  const el = document.createElement('div');
  el.className = 'msg ' + (m.mine ? 'mine' : 'theirs');
  const urls = [];
  if (m.type === 'text') {
    el.textContent = m.text;
    if (EMOJI_ONLY.test(m.text) && !/[0-9#*]/.test(m.text)) el.classList.add('big-emoji');
  } else {
    if (m.type === 'image' && !SAFE_IMAGE.test(m.mime || '')) m = { ...m, type: 'file' };
    if (m.type === 'audio' && !SAFE_AUDIO.test(m.mime || '')) m = { ...m, type: 'file' };
    const shownMime = m.type === 'file' ? 'application/octet-stream' : safeMime(m.mime);
    const blob = new Blob([body], { type: shownMime });
    const url = URL.createObjectURL(blob);
    urls.push(url);
    if (m.type === 'image') {
      const img = document.createElement('img');
      img.src = url; img.alt = 'Bild';
      img.onload = scrollDown;
      el.appendChild(img);
    } else if (m.type === 'audio') {
      const a = document.createElement('audio');
      a.controls = true; a.src = url; a.preload = 'metadata';
      el.appendChild(a);
    } else {
      const a = document.createElement('a');
      a.href = url; a.download = (m.name || 'Dokument').replace(/[\\/]/g, '_');
      a.textContent = '📄 ' + (m.name || 'Dokument') + ' (' + fmtSize(body.length) + ')';
      if (native) {
        // Android-WebView kann keine Blob-Downloads: Datei kurz im App-Cache ablegen und öffnen (wird beim Verlassen gelöscht)
        a.addEventListener('click', (e) => {
          e.preventDefault();
          if (!window.confirm('Dokument mit einer anderen App öffnen? Öffne nur Dateien, die du erwartest.')) return;
          native.openFile({ data: b64(body), name: m.name || 'Dokument', mime: safeMime(m.mime) }).catch(() => toast('Keine App zum Öffnen gefunden.'));
        });
      }
      el.appendChild(a);
    }
  }
  const meta = document.createElement('div');
  meta.className = 'meta';
  const expires = Date.now() + CFG.MESSAGE_TTL_MS;
  meta.dataset.base = fmtTime(Date.now());
  meta.textContent = meta.dataset.base + (m.mine ? ' · gesendet' : '');
  el.appendChild(meta);
  $('messages').appendChild(el);
  ch.messages.push({ id: m.id, el, meta, expires, urls, mine: m.mine });
  scrollDown();
}

function markDelivered(id) {
  const m = channel && channel.messages.find((x) => x.id === id);
  if (m) m.meta.textContent = m.meta.dataset.base + ' · zugestellt';
}

// Nur harmlose Bildformate werden als Bild angezeigt. SVG/HTML usw. gelten immer als Dokument
// und werden nie im App-Fenster geöffnet (Schutz vor eingeschleustem Code).
const SAFE_IMAGE = /^image\/(png|jpe?g|gif|webp)$/i;
const SAFE_AUDIO = /^audio\/(webm|mp4|ogg|mpeg|aac|x-m4a)$/i;
function safeMime(m) { return /^[a-z]+\/[a-z0-9.+-]+$/i.test(m || '') ? m : 'application/octet-stream'; }
function fmtSize(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB'; }

async function sendText() {
  const ta = $('input');
  const text = ta.value.trim();
  if (!text || !channel || !channel.keys) return;
  ta.value = '';
  autoGrow();
  const head = { type: 'text', id: randId(), text };
  renderMessage({ ...head, mine: true });
  sendPayload({ head, body: null, notify: true });
}

async function sendFile(file) {
  if (!file || !channel || !channel.keys) return;
  if (file.size > CFG.MAX_FILE_BYTES) { toast('Die Datei ist zu groß (höchstens 15 MB).'); return; }
  const body = new Uint8Array(await file.arrayBuffer());
  const type = SAFE_IMAGE.test(file.type) ? 'image' : 'file';
  const head = { type, id: randId(), name: file.name, mime: file.type || 'application/octet-stream' };
  renderMessage({ ...head, mine: true }, body);
  sendPayload({ head, body, notify: true });
}

// Selbstlöschung
setInterval(() => {
  const ch = channel;
  if (!ch) return;
  const now = Date.now();
  ch.messages = ch.messages.filter((m) => {
    if (m.expires > now) return true;
    m.urls.forEach((u) => URL.revokeObjectURL(u));
    m.el.remove();
    return false;
  });
  for (const id of [...ch.seen]) if (ch.seen.size > 2000) ch.seen.delete(id);
}, 5000);

async function leaveChannel({ notify = true, silent = false } = {}) {
  const ch = channel;
  if (!ch) return;
  if (notify && ch.keys && ch.state === 'open' && ch.active) {
    try {
      sendQueue.length = 0;
      await sendIdle; // laufende Sendung abwarten, damit die Schlüsselkette sauber bleibt
      enqueue({ head: { type: 'bye', id: randId() }, body: null, notify: false });
      await sendIdle;
      await sleep(300);
    } catch (e) { /* ignore */ }
  }
  ch.state = 'closed';
  clearTimeout(ch.reconnectTimer);
  ch.messages.forEach((m) => m.urls.forEach((u) => URL.revokeObjectURL(u)));
  ch.messages = [];
  ch.outbox.clear();
  if (ch.keys) { wipeBytes(ch.keys.send.chain); wipeBytes(ch.keys.recv.chain); ch.keys.recv.skipped.forEach(wipeBytes); }
  ch.keys = null; ch.kp = null; ch.pw = null; ch.rx.clear(); ch.pending.clear(); ch.active = null;
  sendQueue.length = 0;
  channel = null;
  $('messages').innerHTML = '';
  $('input').value = '';
  stopRecording(true);
  try { await transport.close(); } catch (e) { /* ignore */ }
  if (!silent && isUnlocked) goMenu();
}

// ---------------------------------------------------------------- Scanner
let scanStream = null;
let scanLoop = null;
async function startScan(title) {
  show('screen-scan');
  $('scan-title').textContent = title;
  $('scan-status').textContent = 'Halte die Kamera auf den Code deines Partners.';
  const video = $('scan-video');
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
  } catch (e) {
    $('scan-status').textContent = 'Kein Kamerazugriff. Bitte die Kamera für diese App erlauben.';
    return;
  }
  video.srcObject = scanStream;
  await video.play().catch(() => {});
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  let busy = false;
  scanLoop = setInterval(async () => {
    if (busy || !video.videoWidth) return;
    const scale = Math.min(1, 720 / Math.max(video.videoWidth, video.videoHeight));
    canvas.width = Math.round(video.videoWidth * scale);
    canvas.height = Math.round(video.videoHeight * scale);
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
    if (code && code.data) {
      busy = true;
      stopScanner();
      const ok = await onScanned(code.data);
      if (!ok && currentScreen === 'screen-scan') { busy = false; startScan(title); }
    }
  }, 150);
}
function stopScanner() {
  clearInterval(scanLoop); scanLoop = null;
  if (scanStream) { scanStream.getTracks().forEach((t) => t.stop()); scanStream = null; }
  const v = $('scan-video'); if (v) v.srcObject = null;
}

// ---------------------------------------------------------------- Sprachnachrichten
let rec = null;
async function startRecording() {
  if (rec || !channel || !channel.keys) return;
  let stream;
  try { stream = await navigator.mediaDevices.getUserMedia({ audio: true }); } catch (e) { toast('Kein Mikrofonzugriff. Bitte erlauben.'); return; }
  const types = ['audio/webm;codecs=opus', 'audio/mp4', 'audio/webm', 'audio/ogg;codecs=opus'];
  const mimeType = types.find((t) => window.MediaRecorder && MediaRecorder.isTypeSupported && MediaRecorder.isTypeSupported(t)) || '';
  let mr;
  try { mr = new MediaRecorder(stream, mimeType ? { mimeType } : undefined); } catch (e) { stream.getTracks().forEach((t) => t.stop()); toast('Aufnahme wird hier nicht unterstützt.'); return; }
  const chunks = [];
  mr.ondataavailable = (e) => { if (e.data && e.data.size) chunks.push(e.data); };
  rec = { mr, stream, chunks, start: Date.now(), timer: null, cancel: false };
  rec.timer = setInterval(() => {
    const s = Math.floor((Date.now() - rec.start) / 1000);
    $('rec-time').textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
    if (s >= 300) finishRecording();
  }, 250);
  mr.start(250);
  $('rec-time').textContent = '0:00';
  $('rec-bar').hidden = false;
}
function finishRecording() {
  if (!rec) return;
  const r = rec;
  r.mr.onstop = async () => {
    r.stream.getTracks().forEach((t) => t.stop());
    if (r.cancel || !channel || !channel.keys) return;
    const blob = new Blob(r.chunks, { type: r.mr.mimeType || 'audio/webm' });
    const body = new Uint8Array(await blob.arrayBuffer());
    if (body.length > CFG.MAX_FILE_BYTES) { toast('Sprachnachricht zu lang.'); return; }
    const head = { type: 'audio', id: randId(), mime: (r.mr.mimeType || 'audio/webm').split(';')[0] };
    renderMessage({ ...head, mine: true }, body);
    sendPayload({ head, body, notify: true });
  };
  clearInterval(r.timer);
  try { r.mr.stop(); } catch (e) { /* ignore */ }
  rec = null;
  $('rec-bar').hidden = true;
}
function stopRecording(cancel) {
  if (!rec) return;
  rec.cancel = !!cancel;
  finishRecording();
}

// ---------------------------------------------------------------- Emojis
const EMOJIS = '😀 😂 🥲 😊 😍 😘 😎 🤔 😴 😢 😭 😡 🤯 🥳 😇 🙃 👍 👎 👏 🙏 💪 🤝 👋 ✌️ ❤️ 🧡 💛 💚 💙 💜 🖤 💯 🔥 ✨ 🎉 🎁 ☕ 🍕 🍻 ⚽ 🚗 ✈️ 🏠 📷 🎵 📞 ⏰ ✅ ❌ ❓ ❗ 🔒 🌙 ☀️ 🌧️ 🌹'.split(' ');
function buildEmojiPanel() {
  const p = $('emoji-panel');
  EMOJIS.forEach((e) => {
    const b = document.createElement('button');
    b.textContent = e;
    b.onclick = () => {
      const ta = $('input');
      const s = ta.selectionStart ?? ta.value.length;
      ta.value = ta.value.slice(0, s) + e + ta.value.slice(ta.selectionEnd ?? s);
      ta.focus();
      ta.selectionStart = ta.selectionEnd = s + e.length;
      autoGrow();
    };
    p.appendChild(b);
  });
}
function autoGrow() { const ta = $('input'); ta.style.height = 'auto'; ta.style.height = Math.min(120, ta.scrollHeight) + 'px'; }

// ---------------------------------------------------------------- Verdrahtung
function wire() {
  $('setup-btn').onclick = setupPassword;
  $('setup-pw2').addEventListener('keydown', (e) => { if (e.key === 'Enter') setupPassword(); });
  $('lock-btn').onclick = tryUnlock;
  $('lock-pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') tryUnlock(); });
  $('menu-lock').onclick = lockApp;
  $('btn-new').onclick = () => startChannelFlow('A');
  $('btn-scan').onclick = () => startChannelFlow('B');
  $('btn-info').onclick = () => show('screen-info');
  $('btn-reset').onclick = async () => {
    if (window.confirm('Wirklich alles löschen? Das Passwort wird entfernt und die App neu eingerichtet.')) await wipeEverything();
  };
  $('chpw').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('chpw-btn').click(); });
  document.querySelectorAll('[data-back]').forEach((b) => { b.onclick = goBack; });
  $('chat-leave').onclick = () => {
    if (window.confirm('Kanal verlassen? Alle Nachrichten werden bei beiden gelöscht.')) leaveChannel({ notify: true });
  };
  $('btn-send').onclick = sendText;
  $('input').addEventListener('input', autoGrow);
  $('input').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey && !('ontouchstart' in window)) { e.preventDefault(); sendText(); } });
  $('btn-attach').onclick = () => $('file-input').click();
  $('file-input').onchange = (e) => { const f = e.target.files && e.target.files[0]; e.target.value = ''; sendFile(f); };
  $('btn-emoji').onclick = () => { $('emoji-panel').hidden = !$('emoji-panel').hidden; };
  $('btn-mic').onclick = () => { if (rec) finishRecording(); else startRecording(); };
  $('rec-send').onclick = () => finishRecording();
  $('rec-cancel').onclick = () => stopRecording(true);
  buildEmojiPanel();
}

async function goBack() {
  stopScanner();
  if (channel && channel.state === 'setup') await leaveChannel({ notify: false, silent: true });
  const prev = backStack.pop();
  if (prev && prev !== 'screen-chpw' && prev !== 'screen-scan' && prev !== 'screen-show') show(prev, { push: false });
  else goMenu();
}

if (native) {
  // Android-Zurück-Taste
  try { AppPlugin.addListener('backButton', () => { if (currentScreen !== 'screen-chat' && currentScreen !== 'screen-lock' && currentScreen !== 'screen-setup') goBack(); }); } catch (e) { /* ignore */ }
}

wire();
if (lsGet(LS_HASH) && (parseInt(lsGet(LS_FAILS) || '0', 10) || 0) >= CFG.MAX_ATTEMPTS) wipeEverything();
else show(lsGet(LS_HASH) ? 'screen-lock' : 'screen-setup', { push: false });
