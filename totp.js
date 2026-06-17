// =====================================================
// totp.js — Google Authenticator (TOTP RFC 6238)
// =====================================================

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Genera un secreto TOTP aleatorio en Base32 (20 bytes = 160 bits) */
export function generateSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  return Array.from(bytes).map(b => BASE32_CHARS[b & 31]).join('');
}

/** Decodifica Base32 → Uint8Array */
function base32Decode(str) {
  str = str.replace(/\s/g, '').replace(/=+$/, '').toUpperCase();
  const out = [];
  let buf = 0, bits = 0;
  for (const ch of str) {
    const v = BASE32_CHARS.indexOf(ch);
    if (v < 0) continue;
    buf = (buf << 5) | v;
    bits += 5;
    if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); }
  }
  return new Uint8Array(out);
}

/** Genera el código TOTP para un counter dado (usa HMAC-SHA1 vía Web Crypto) */
async function hotp(secret, counter) {
  const key   = base32Decode(secret);
  const msg   = new ArrayBuffer(8);
  new DataView(msg).setUint32(4, counter >>> 0, false);
  const ck    = await crypto.subtle.importKey('raw', key, { name:'HMAC', hash:'SHA-1' }, false, ['sign']);
  const sig   = new Uint8Array(await crypto.subtle.sign('HMAC', ck, msg));
  const off   = sig[19] & 0xf;
  const num   = ((sig[off]&0x7f)<<24|(sig[off+1])<<16|(sig[off+2])<<8|(sig[off+3])) % 1_000_000;
  return num.toString().padStart(6, '0');
}

/** Verifica un código TOTP (ventana ±1 intervalo para compensar desfase de reloj) */
export async function verifyCode(secret, code) {
  if (!secret || !code || code.length !== 6) return false;
  const counter = Math.floor(Date.now() / 1000 / 30);
  for (const d of [0, -1, 1]) {
    if (await hotp(secret, counter + d) === code.trim()) return true;
  }
  return false;
}

/** Genera el código actual (para testing / countdown) */
export async function currentCode(secret) {
  return hotp(secret, Math.floor(Date.now() / 1000 / 30));
}

/** Segundos hasta el próximo código */
export function secondsLeft() {
  return 30 - (Math.floor(Date.now() / 1000) % 30);
}

/** URI otpauth para el QR */
export function otpauthUri(secret, label = 'MyPass') {
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=MyPass&algorithm=SHA1&digits=6&period=30`;
}

/** URL de imagen QR (api.qrserver.com — gratis, sin API key) */
export function qrImageUrl(secret, label = 'MyPass') {
  const uri = encodeURIComponent(otpauthUri(secret, label));
  return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&ecc=M&data=${uri}`;
}

/** Deriva la clave de recuperación a partir del secreto TOTP */
export async function deriveRecoveryKey(totpSecret) {
  const raw = new TextEncoder().encode(totpSecret);
  const km  = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt: new TextEncoder().encode('mypass-recovery-2026'), iterations:100_000, hash:'SHA-256' },
    km, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']
  );
}

/** Cifra la vault key (raw bytes) con la recovery key */
export async function encryptKeyForRecovery(vaultKey, recoveryKey) {
  const raw = await crypto.subtle.exportKey('raw', vaultKey);
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, recoveryKey, raw);
  const b64 = u8 => btoa(String.fromCharCode(...u8));
  return { blob: b64(new Uint8Array(enc)), iv: b64(iv) };
}

/** Descifra la vault key desde el blob de recuperación */
export async function decryptKeyFromRecovery(blob64, iv64, recoveryKey) {
  const from = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const raw  = await crypto.subtle.decrypt({ name:'AES-GCM', iv: from(iv64) }, recoveryKey, from(blob64));
  return crypto.subtle.importKey('raw', raw, { name:'AES-GCM', length:256 }, true, ['encrypt','decrypt']);
}
