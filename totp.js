// =====================================================
// totp.js — Google Authenticator (TOTP RFC 6238)
// SHA-1 y HMAC implementados en JS puro (sin crypto.subtle)
// para máxima compatibilidad con todos los browsers.
// =====================================================

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// ── SHA-1 puro JS ────────────────────────────────────
function sha1(data) {
  const bytes = [...data];
  const bitLen = bytes.length * 8;
  bytes.push(0x80);
  while ((bytes.length % 64) !== 56) bytes.push(0);
  for (let i = 7; i >= 0; i--) bytes.push((bitLen / Math.pow(2, i * 8)) & 0xff);
  const W = new Array(80);
  const rol = (n, s) => ((n << s) | (n >>> (32 - s))) >>> 0;
  let H0=0x67452301, H1=0xEFCDAB89, H2=0x98BADCFE, H3=0x10325476, H4=0xC3D2E1F0;
  for (let c = 0; c < bytes.length; c += 64) {
    for (let i = 0; i < 16; i++)
      W[i] = (bytes[c+i*4]<<24|bytes[c+i*4+1]<<16|bytes[c+i*4+2]<<8|bytes[c+i*4+3]) >>> 0;
    for (let i = 16; i < 80; i++) W[i] = rol(W[i-3]^W[i-8]^W[i-14]^W[i-16], 1);
    let [a,b,d,e,f] = [H0,H1,H2,H3,H4];
    for (let i = 0; i < 80; i++) {
      let fn, k;
      if (i<20) { fn=(b&d)|(~b&e)>>>0; k=0x5A827999; }
      else if (i<40) { fn=b^d^e; k=0x6ED9EBA1; }
      else if (i<60) { fn=(b&d)|(b&e)|(d&e); k=0x8F1BBCDC; }
      else { fn=b^d^e; k=0xCA62C1D6; }
      const t = (rol(a,5) + fn + f + k + W[i]) >>> 0;
      f=e; e=d; d=rol(b,30); b=a; a=t;
    }
    H0=(H0+a)>>>0; H1=(H1+b)>>>0; H2=(H2+d)>>>0; H3=(H3+e)>>>0; H4=(H4+f)>>>0;
  }
  const r = [];
  for (const h of [H0,H1,H2,H3,H4])
    r.push((h>>>24)&0xff,(h>>>16)&0xff,(h>>>8)&0xff,h&0xff);
  return r;
}

// ── HMAC-SHA1 puro JS ─────────────────────────────────
function hmacSha1(key, msg) {
  const B = 64;
  if (key.length > B) key = sha1(key);
  while (key.length < B) key.push(0);
  const ip = key.map(b => b ^ 0x36);
  const op = key.map(b => b ^ 0x5C);
  return sha1([...op, ...sha1([...ip, ...msg])]);
}

// ── Base32 ────────────────────────────────────────────
function base32Decode(str) {
  str = str.replace(/\s|=/g, '').toUpperCase();
  const out = [];
  let buf = 0, bits = 0;
  for (const ch of str) {
    const v = BASE32.indexOf(ch);
    if (v < 0) continue;
    buf = (buf << 5) | v;
    bits += 5;
    if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); }
  }
  return out;
}

export function generateSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let out = '', buf = 0, bits = 0;
  for (const b of bytes) {
    buf = (buf << 8) | b; bits += 8;
    while (bits >= 5) { bits -= 5; out += BASE32[(buf >> bits) & 31]; }
  }
  return out; // 32 chars
}

// ── HOTP / TOTP ──────────────────────────────────────
function hotp(secretB32, counter) {
  const key = base32Decode(secretB32);
  const msg = [0,0,0,0,
    (counter >>> 24) & 0xff,
    (counter >>> 16) & 0xff,
    (counter >>>  8) & 0xff,
     counter         & 0xff];
  const sig = hmacSha1(key, msg);
  const off = sig[19] & 0xf;
  const num = ((sig[off]&0x7f)<<24|(sig[off+1])<<16|(sig[off+2])<<8|sig[off+3]) % 1_000_000;
  return num.toString().padStart(6, '0');
}

export function verifyCode(secret, code) {
  if (!secret || !code || String(code).trim().length !== 6) return false;
  const counter = Math.floor(Date.now() / 1000 / 30);
  const c = String(code).trim();
  return [0, -1, 1].some(d => hotp(secret, counter + d) === c);
}

export function currentCode(secret) {
  return hotp(secret, Math.floor(Date.now() / 1000 / 30));
}

export function secondsLeft() {
  return 30 - (Math.floor(Date.now() / 1000) % 30);
}

export function otpauthUri(secret, label = 'MyPass') {
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=MyPass&algorithm=SHA1&digits=6&period=30`;
}

// ── Recovery (usa crypto.subtle solo para AES, no para TOTP) ──
export async function deriveRecoveryKey(totpSecret) {
  const raw = new TextEncoder().encode(totpSecret);
  const km  = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt:new TextEncoder().encode('mypass-recovery-2026'), iterations:100_000, hash:'SHA-256' },
    km, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']
  );
}

export async function encryptKeyForRecovery(vaultKey, recoveryKey) {
  const raw = await crypto.subtle.exportKey('raw', vaultKey);
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, recoveryKey, raw);
  const b64 = u8 => btoa(String.fromCharCode(...new Uint8Array(u8)));
  return { blob: b64(enc), iv: b64(iv) };
}

export async function decryptKeyFromRecovery(blob64, iv64, recoveryKey) {
  const from = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const raw  = await crypto.subtle.decrypt({ name:'AES-GCM', iv:from(iv64) }, recoveryKey, from(blob64));
  return crypto.subtle.importKey('raw', raw, { name:'AES-GCM', length:256 }, true, ['encrypt','decrypt']);
}
