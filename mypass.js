// =====================================================
// My Pass — App principal
// =====================================================
import { credRowHTML, getColor, getInitial } from './credrow.js';
import {
  generateSecret, verifyCode, secondsLeft, otpauthUri,
  deriveRecoveryKey, encryptKeyForRecovery, decryptKeyFromRecovery
} from './totp.js';

// ── Config ───────────────────────────────────────────
const SUPA_URL  = 'https://tblujfduscslxjmrjbdr.supabase.co';
const SUPA_KEY  = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRibHVqZmR1c2NzbHhqbXJqYmRyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODExMDU3NTcsImV4cCI6MjA5NjY4MTc1N30.0zudypPzlrOQ6dDa1Vp2XFFDL4Ea8dep1r3KMuEZGn0';
const VAULT_ID  = 'main';

// ── Estado ───────────────────────────────────────────
let S = {
  // Auth
  locked: true, pin: '', showPin: false,
  authStep: 'password',  // 'password' | 'totp-verify' | 'totp-setup-scan' | 'totp-setup-confirm'
                          // | 'recovery-1' | 'recovery-2' | 'recovery-new-pwd'
  totpCode: '', totpCode2: '', recoveryNewPwd: '',
  totpSecret: null,        // sólo durante setup
  countdownSec: 30, countdownTimer: null,
  recoveryKey: null,       // vault key recuperada (antes de poner nueva pwd)
  // App
  screen: 'vault', query: '', catFilter: 'all',
  selectedId: null, revealed: false, editingId: null,
  form: { platform:'', type:'password', username:'', email:'', secret:'', url:'', tags:'', note:'' },
  gen: { length: 20, upper:true, lower:true, numbers:true, symbols:true, value:'' },
  creds: [], toast: null, loading: false,
  cryptoKey: null, saltB64: null,
};

// ── Crypto ───────────────────────────────────────────
const enc     = s  => new TextEncoder().encode(s);
const b64     = u8 => btoa(String.fromCharCode(...u8));
const fromB64 = s  => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function deriveKey(password, salt) {
  const km = await crypto.subtle.importKey('raw', enc(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:100_000, hash:'SHA-256' },
    km, { name:'AES-GCM', length:256 }, true, ['encrypt','decrypt']  // extractable:true para recovery
  );
}
async function encryptVault(key, data) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const buf = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, enc(JSON.stringify(data)));
  return { iv: b64(iv), data: b64(new Uint8Array(buf)) };
}
async function decryptVault(key, iv64, data64) {
  const buf = await crypto.subtle.decrypt({ name:'AES-GCM', iv:fromB64(iv64) }, key, fromB64(data64));
  return JSON.parse(new TextDecoder().decode(buf));
}

// ── Supabase ─────────────────────────────────────────
async function supaFetch(path, opts={}) {
  const r = await fetch(`${SUPA_URL}/rest/v1/${path}`, {
    headers:{ apikey:SUPA_KEY, Authorization:`Bearer ${SUPA_KEY}`, 'Content-Type':'application/json', ...opts.headers },
    ...opts
  });
  const t = await r.text(); return t ? JSON.parse(t) : null;
}
async function loadVaultRow() {
  try { const rows = await supaFetch(`mypass_vault?id=eq.${VAULT_ID}&select=*`); return rows?.[0]??null; }
  catch { return null; }
}
async function saveVaultRow(data) {
  await supaFetch('mypass_vault', {
    method:'POST', headers:{ Prefer:'resolution=merge-duplicates' },
    body: JSON.stringify({ id:VAULT_ID, updated_at:new Date().toISOString(), ...data })
  });
}
async function persist() {
  if (!S.cryptoKey) return;
  const e = await encryptVault(S.cryptoKey, S.creds);
  await saveVaultRow({ encrypted_data:e.data, iv:e.iv, salt:S.saltB64 });
}

// ── Helpers ──────────────────────────────────────────
function uid()  { return Date.now().toString(36)+Math.random().toString(36).slice(2); }
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function fmtDate(iso) { return iso?new Date(iso).toLocaleDateString('es-CO',{day:'numeric',month:'long',year:'numeric'}):''; }
function secretLabel(t) { return t==='token'?'Token':t==='api'?'API key':'Contraseña'; }

// ── Fuerza ───────────────────────────────────────────
function strength(pw) {
  if (!pw) return { score:0, label:'—', color:'#5a5a60', pct:4 };
  let s=0;
  if (pw.length>=8) s++; if (pw.length>=14) s++;
  if (/[a-z]/.test(pw)&&/[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  const map=[{l:'Muy débil',c:'#f87171'},{l:'Muy débil',c:'#f87171'},{l:'Débil',c:'#fb923c'},{l:'Media',c:'#fbbf24'},{l:'Fuerte',c:'#a3e635'},{l:'Muy fuerte',c:'#4ade80'}];
  return { score:s, label:map[s].l, color:map[s].c, pct:Math.max(8,(s/5)*100) };
}

// ── Generador ────────────────────────────────────────
function genPassword(g) {
  let pool='';
  if(g.lower)   pool+='abcdefghijkmnpqrstuvwxyz';
  if(g.upper)   pool+='ABCDEFGHJKLMNPQRSTUVWXYZ';
  if(g.numbers) pool+='23456789';
  if(g.symbols) pool+='!@#$%^&*-_=+?';
  if(!pool) pool='abcdefghijklmnopqrstuvwxyz';
  const bytes = crypto.getRandomValues(new Uint8Array(g.length));
  return Array.from(bytes).map(b=>pool[b%pool.length]).join('');
}

// ── Derivados ────────────────────────────────────────
function derived() {
  const counts={};
  S.creds.forEach(c=>{ counts[c.secret]=(counts[c.secret]||0)+1; });
  const all=S.creds.map(c=>{ const st=strength(c.secret); return {...c,st,weak:(c.type==='password'&&st.score<=2),reused:(c.type==='password'&&counts[c.secret]>1)}; });
  const q=S.query.toLowerCase();
  const matches=c=>!q||`${c.platform} ${c.username||''} ${c.email||''} ${(c.tags||[]).join(' ')}`.toLowerCase().includes(q);
  const vault=all.filter(matches).sort((a,b)=>(b.fav?1:0)-(a.fav?1:0));
  const cats=all.filter(matches).filter(c=>S.catFilter==='all'||c.type===S.catFilter);
  const countPwd=all.filter(c=>c.type==='password').length;
  const countTok=all.filter(c=>c.type==='token').length;
  const countApi=all.filter(c=>c.type==='api').length;
  const strong=all.filter(c=>c.type==='password'&&c.st.score>=4).length;
  const healthScore=countPwd?Math.round((strong/countPwd)*100):100;
  return { vault, cats, countPwd, countTok, countApi, healthScore, weakList:all.filter(c=>c.weak), reusedList:all.filter(c=>c.reused) };
}

// ── ICONS ────────────────────────────────────────────
const I = {
  lock:   `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2.6"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/><circle cx="12" cy="16" r="1.5" fill="currentColor" stroke="none"/></svg>`,
  eye:    `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>`,
  eyeOff: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3l18 18"/><path d="M10.6 10.6a3 3 0 0 0 4.2 4.2"/><path d="M9.4 5.2A9.5 9.5 0 0 1 12 5c6.5 0 10 7 10 7a16 16 0 0 1-3.4 4"/><path d="M6.4 6.4A16 16 0 0 0 2 12s3.5 7 10 7a9 9 0 0 0 3-.5"/></svg>`,
  copy:   `<svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
  plus:   `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
  search: `<svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
  chevL:  `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>`,
  refresh:`<svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>`,
  key:    `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>`,
  layers: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>`,
  shield: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`,
  star:   `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
  starFill:`<svg width="20" height="20" viewBox="0 0 24 24" fill="#4ade80" stroke="none"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
  edit:   `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`,
  clock:  `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
  check:  `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
  checkSm:`<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
  shieldSm:`<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`,
  phone:  `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>`,
  bat:    `<svg width="24" height="12" viewBox="0 0 24 12" fill="none"><rect x="0.5" y="0.5" width="20" height="11" rx="3" stroke="#ECECEA" stroke-opacity="0.5"/><rect x="2" y="2" width="14.5" height="8" rx="1.5" fill="#ECECEA"/><rect x="22" y="3.6" width="2" height="4.8" rx="1" fill="#ECECEA" fill-opacity="0.5"/></svg>`,
  sig:    `<svg width="18" height="12" viewBox="0 0 18 12" fill="#ECECEA"><rect x="0" y="8" width="3" height="4" rx="1"/><rect x="5" y="5.5" width="3" height="6.5" rx="1"/><rect x="10" y="2.8" width="3" height="9.2" rx="1"/><rect x="15" y="0" width="3" height="12" rx="1" fill-opacity="0.4"/></svg>`,
};

// ── Status / Nav ─────────────────────────────────────
function statusBarHTML() {
  const now=new Date(), t=`${now.getHours().toString().padStart(2,'0')}:${now.getMinutes().toString().padStart(2,'0')}`;
  return `<div class="mp-statusbar"><span class="mp-statusbar-time">${t}</span><div style="display:flex;align-items:center;gap:7px;">${I.sig}${I.bat}</div></div>`;
}
function navHTML(active) {
  const tabs=[{id:'vault',label:'Bóveda',icon:I.lock},{id:'categories',label:'Categorías',icon:I.layers},{id:'generator',label:'Generar',icon:I.key},{id:'audit',label:'Salud',icon:I.shield}];
  return `<nav class="mp-nav">${tabs.map(t=>`<button class="mp-nav-tab ${active===t.id?'active':''}" onclick="GO('${t.id}')"><span style="color:${active===t.id?'#4ade80':'#52525b'}">${t.icon}</span><span class="label">${t.label}</span></button>`).join('')}</nav>`;
}

// ── Input TOTP (6 dígitos individuales) ──────────────
function totpInputHTML(id='totp-main') {
  return `<div class="mp-totp-input" id="${id}">
    ${[0,1,2,3,4,5].map(i=>`<input class="mp-totp-digit" type="text" inputmode="numeric" maxlength="1" data-idx="${i}" autocomplete="off">`).join('')}
  </div>`;
}
function bindTotpInput(containerId, onComplete) {
  const container=document.getElementById(containerId); if(!container)return;
  const inputs=[...container.querySelectorAll('.mp-totp-digit')];
  inputs.forEach((inp,i)=>{
    inp.addEventListener('input',e=>{
      const v=e.target.value.replace(/\D/g,'');
      e.target.value=v;
      if(v && i<5) inputs[i+1].focus();
      const code=inputs.map(x=>x.value).join('');
      if(code.length===6) onComplete(code);
    });
    inp.addEventListener('keydown',e=>{
      if(e.key==='Backspace'&&!inp.value&&i>0) inputs[i-1].focus();
      if(e.key==='ArrowLeft'&&i>0) inputs[i-1].focus();
      if(e.key==='ArrowRight'&&i<5) inputs[i+1].focus();
    });
    inp.addEventListener('paste',e=>{
      e.preventDefault();
      const pasted=(e.clipboardData||window.clipboardData).getData('text').replace(/\D/g,'').slice(0,6);
      pasted.split('').forEach((ch,j)=>{ if(inputs[j]) inputs[j].value=ch; });
      if(pasted.length===6) { inputs[5].focus(); onComplete(pasted); }
    });
  });
  inputs[0]?.focus();
}

// ── PANTALLAS DE AUTH ─────────────────────────────────

function screenLock() {
  const step=S.authStep;

  // ── Contraseña maestra
  if(step==='password') return `
    <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:0 38px;text-align:center;animation:mp-fade .4s ease;">
      <div style="width:80px;height:80px;border-radius:25px;background:linear-gradient(150deg,#4ade80,#1f9a52);display:flex;align-items:center;justify-content:center;box-shadow:0 18px 44px rgba(74,222,128,0.3);margin-bottom:28px;"><span style="color:#04240f;">${I.lock}</span></div>
      <div style="font-size:28px;font-weight:700;color:#fff;letter-spacing:-0.7px;">My Pass</div>
      <div style="font-size:14px;color:#7b7b82;margin-top:8px;max-width:240px;line-height:1.5;">Tu bóveda cifrada de extremo a extremo</div>
      <div class="mp-input-wrap" style="width:100%;margin-top:40px;">
        <input id="pinInput" class="mp-input mono" type="${S.showPin?'text':'password'}" placeholder="Contraseña maestra"
          oninput="S.pin=this.value" onkeydown="if(event.key==='Enter')UNLOCK()" style="letter-spacing:1px;" autocomplete="current-password">
        <button class="mp-input-ico" onclick="S.showPin=!S.showPin;render()" style="color:#6b6b72;">${S.showPin?I.eyeOff:I.eye}</button>
      </div>
      ${S.loading
        ? `<div style="margin-top:18px;display:flex;align-items:center;gap:10px;color:#4ade80;font-size:14px;"><div class="mp-spin"></div>Verificando…</div>`
        : `<button class="mp-btn-primary" style="width:100%;margin-top:14px;" onclick="UNLOCK()">${I.lock} Desbloquear</button>
           <button onclick="S.authStep='recovery-1';render()" style="background:none;border:none;color:#7b7b82;font-size:13px;cursor:pointer;margin-top:16px;text-decoration:underline;">Olvidé mi contraseña maestra</button>`}
      <div style="position:absolute;bottom:28px;left:50%;transform:translateX(-50%);display:flex;align-items:center;gap:6px;font-size:11.5px;color:#4d4d54;white-space:nowrap;">${I.shieldSm} Cifrado AES‑256 · Conocimiento cero</div>
    </div>`;

  // ── Verificar TOTP tras contraseña
  if(step==='totp-verify') return `
    <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:0 32px;text-align:center;animation:mp-fade .3s ease;">
      <div style="width:64px;height:64px;border-radius:20px;background:rgba(74,222,128,0.12);border:1px solid rgba(74,222,128,0.3);display:flex;align-items:center;justify-content:center;margin-bottom:24px;color:#4ade80;">${I.phone}</div>
      <div style="font-size:21px;font-weight:700;color:#ECECEA;letter-spacing:-0.5px;">Verificación en 2 pasos</div>
      <div style="font-size:13.5px;color:#7b7b82;margin-top:8px;line-height:1.5;">Ingresa el código de Google Authenticator</div>
      ${totpInputHTML('totp-main')}
      ${S.loading?`<div style="display:flex;align-items:center;gap:10px;color:#4ade80;font-size:14px;"><div class="mp-spin"></div>Verificando…</div>`:''}
      <button onclick="S.authStep='password';S.pin='';render()" style="background:none;border:none;color:#7b7b82;font-size:13px;cursor:pointer;margin-top:20px;">← Volver</button>
    </div>`;

  // ── Setup TOTP: mostrar QR
  if(step==='totp-setup-scan') return `
    <div style="position:absolute;inset:0;overflow-y:auto;display:flex;flex-direction:column;align-items:center;padding:28px 28px 40px;text-align:center;animation:mp-fade .3s ease;">
      <div style="display:flex;gap:6px;margin-bottom:24px;">${[1,2].map(n=>`<div class="mp-step-dot ${n===1?'active':''}"></div>`).join('')}</div>
      <div style="font-size:21px;font-weight:700;color:#ECECEA;letter-spacing:-0.5px;">Configura Google Authenticator</div>
      <div style="font-size:13px;color:#7b7b82;margin-top:8px;line-height:1.5;max-width:280px;">Abre la app, toca <strong style="color:#ECECEA;">+</strong> → <strong style="color:#ECECEA;">Escanear código QR</strong></div>
      <div class="mp-qr-wrap"><div id="qr-render" style="width:168px;height:168px;"></div></div>
      <div style="font-size:11px;color:#5a5a60;margin-bottom:8px;">¿No puedes escanear? Ingresa el código manual:</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:#4ade80;letter-spacing:2px;word-break:break-all;background:rgba(74,222,128,0.07);border:1px solid rgba(74,222,128,0.2);border-radius:10px;padding:10px 14px;margin-bottom:24px;">${S.totpSecret}</div>
      <button class="mp-btn-primary" style="width:100%;" onclick="S.authStep='totp-setup-confirm';render()">Ya lo escaneé →</button>
    </div>`;

  // ── Setup TOTP: confirmar código
  if(step==='totp-setup-confirm') return `
    <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:0 32px;text-align:center;animation:mp-fade .3s ease;">
      <div style="display:flex;gap:6px;margin-bottom:24px;">${[1,2].map(n=>`<div class="mp-step-dot ${n===2?'active':''}"></div>`).join('')}</div>
      <div style="font-size:21px;font-weight:700;color:#ECECEA;letter-spacing:-0.5px;">Confirma el código</div>
      <div style="font-size:13.5px;color:#7b7b82;margin-top:8px;margin-bottom:20px;line-height:1.5;">Ingresa el código de 6 dígitos que ves en Google Authenticator</div>
      ${totpInputHTML('totp-confirm')}

      ${S.loading?`<div style="display:flex;align-items:center;gap:10px;color:#4ade80;font-size:14px;"><div class="mp-spin"></div>Activando…</div>`:''}
      <button onclick="S.authStep='totp-setup-scan';render()" style="background:none;border:none;color:#7b7b82;font-size:13px;cursor:pointer;margin-top:20px;">← Ver QR de nuevo</button>
    </div>`;

  // ── Recuperación: primer código
  if(step==='recovery-1') return `
    <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:0 32px;text-align:center;animation:mp-fade .3s ease;">
      <div style="display:flex;gap:6px;margin-bottom:24px;">${[1,2,3].map(n=>`<div class="mp-step-dot ${n===1?'active':''}"></div>`).join('')}</div>
      <div style="font-size:21px;font-weight:700;color:#ECECEA;letter-spacing:-0.5px;">Recuperar acceso</div>
      <div style="font-size:13.5px;color:#7b7b82;margin-top:8px;line-height:1.5;max-width:260px;">Ingresa el <strong style="color:#ECECEA;">código actual</strong> de Google Authenticator</div>
      ${totpInputHTML('totp-rec1')}
      ${S.loading?`<div style="display:flex;align-items:center;gap:10px;color:#4ade80;font-size:14px;"><div class="mp-spin"></div>Verificando…</div>`:''}
      <button onclick="S.authStep='password';render()" style="background:none;border:none;color:#7b7b82;font-size:13px;cursor:pointer;margin-top:20px;">← Volver</button>
    </div>`;

  // ── Recuperación: segundo código (esperar 30s)
  if(step==='recovery-2') return `
    <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:0 32px;text-align:center;animation:mp-fade .3s ease;">
      <div style="display:flex;gap:6px;margin-bottom:24px;">${[1,2,3].map(n=>`<div class="mp-step-dot ${n===2?'active':''}"></div>`).join('')}</div>
      <div style="font-size:21px;font-weight:700;color:#ECECEA;letter-spacing:-0.5px;">Espera el siguiente código</div>
      <div style="font-size:13.5px;color:#7b7b82;margin-top:8px;line-height:1.5;max-width:260px;">Renueva en Google Authenticator e ingresa el <strong style="color:#ECECEA;">nuevo código</strong></div>
      <div class="mp-countdown ${S.countdownSec<=10?'urgent':''}" id="countdown">${S.countdownSec}s</div>
      ${totpInputHTML('totp-rec2')}
      ${S.loading?`<div style="display:flex;align-items:center;gap:10px;color:#4ade80;font-size:14px;"><div class="mp-spin"></div>Verificando…</div>`:''}
    </div>`;

  // ── Recuperación: nueva contraseña
  if(step==='recovery-new-pwd') return `
    <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:0 38px;text-align:center;animation:mp-fade .3s ease;">
      <div style="display:flex;gap:6px;margin-bottom:24px;">${[1,2,3].map(n=>`<div class="mp-step-dot ${n===3?'active':''}"></div>`).join('')}</div>
      <div style="font-size:21px;font-weight:700;color:#ECECEA;letter-spacing:-0.5px;">Nueva contraseña maestra</div>
      <div style="font-size:13.5px;color:#7b7b82;margin-top:8px;margin-bottom:28px;line-height:1.5;">Identidad verificada ✓<br>Elige tu nueva contraseña</div>
      <div class="mp-input-wrap" style="width:100%;">
        <input class="mp-input mono" type="${S.showPin?'text':'password'}" placeholder="Nueva contraseña maestra"
          oninput="S.recoveryNewPwd=this.value" onkeydown="if(event.key==='Enter')RECOVERY_SAVE()" style="letter-spacing:1px;">
        <button class="mp-input-ico" onclick="S.showPin=!S.showPin;render()" style="color:#6b6b72;">${S.showPin?I.eyeOff:I.eye}</button>
      </div>
      ${S.loading?`<div style="margin-top:18px;display:flex;align-items:center;gap:10px;color:#4ade80;font-size:14px;"><div class="mp-spin"></div>Guardando…</div>`
        :`<button class="mp-btn-primary" style="width:100%;margin-top:14px;" onclick="RECOVERY_SAVE()">${I.check} Guardar y entrar</button>`}
    </div>`;

  return '';
}

// ── PANTALLAS APP ─────────────────────────────────────
function screenVault() {
  const {vault}=derived();
  return `
    <div style="display:flex;align-items:center;justify-content:space-between;padding-top:10px;margin-bottom:20px;">
      <div><h1 style="font-size:27px;font-weight:700;color:#ECECEA;letter-spacing:-0.7px;">Mi bóveda</h1>
      <p style="font-size:13px;color:#7b7b82;margin-top:2px;">${S.creds.length} credencial${S.creds.length!==1?'es':''} cifrada${S.creds.length!==1?'s':''}</p></div>
      <button class="mp-btn-icon" onclick="LOCK()">${I.lock}</button>
    </div>
    <div class="mp-input-wrap" style="margin-bottom:16px;">
      <input class="mp-input" type="text" placeholder="Buscar cuenta, usuario, etiqueta…" value="${esc(S.query)}" oninput="S.query=this.value;render()" style="padding-left:44px;">
      <span style="position:absolute;left:14px;top:50%;transform:translateY(-50%);color:#4d4d54;pointer-events:none;">${I.search}</span>
    </div>
    ${vault.length===0?`<div style="text-align:center;color:#5a5a60;padding:40px 0;font-size:14px;">${S.creds.length===0?'Agrega tu primera credencial con el botón +':'Sin resultados'}</div>`:vault.map(c=>credRowHTML(c)).join('')}
    <button class="mp-fab" onclick="OPEN_ADD()"><span style="color:#052012;">${I.plus}</span></button>
    ${navHTML('vault')}`;
}
function screenCategories() {
  const {cats,countPwd,countTok,countApi}=derived();
  const p=S.catFilter;
  const pills=[{id:'all',label:`Todo · ${S.creds.length}`},{id:'password',label:`Contraseñas · ${countPwd}`},{id:'token',label:`Tokens · ${countTok}`},{id:'api',label:`APIs · ${countApi}`}];
  return `
    <h1 style="font-size:27px;font-weight:700;color:#ECECEA;letter-spacing:-0.7px;padding-top:10px;margin-bottom:20px;">Categorías</h1>
    <div style="display:flex;gap:8px;overflow-x:auto;scrollbar-width:none;margin-bottom:16px;padding-bottom:4px;">
      ${pills.map(pi=>`<button class="mp-pill ${p===pi.id?'on':'off'}" onclick="S.catFilter='${pi.id}';render()">${pi.label}</button>`).join('')}
    </div>
    ${cats.length===0?`<div style="text-align:center;color:#5a5a60;padding:40px 0;font-size:14px;">Sin elementos en esta categoría</div>`:cats.map(c=>credRowHTML(c)).join('')}
    <button class="mp-fab" onclick="OPEN_ADD()"><span style="color:#052012;">${I.plus}</span></button>
    ${navHTML('categories')}`;
}
function screenGenerator() {
  const g=S.gen; const st=strength(g.value);
  const checks=[{k:'upper',label:'Mayúsculas A–Z'},{k:'lower',label:'Minúsculas a–z'},{k:'numbers',label:'Números 0–9'},{k:'symbols',label:'Símbolos !@#$'}];
  return `
    <h1 style="font-size:27px;font-weight:700;color:#ECECEA;letter-spacing:-0.7px;padding-top:10px;margin-bottom:6px;">Generador</h1>
    <p style="font-size:13px;color:#7b7b82;margin-bottom:20px;">Crea contraseñas seguras al instante</p>
    <div class="mp-card" style="background:linear-gradient(135deg,rgba(74,222,128,0.06),rgba(74,222,128,0.02));border-color:rgba(74,222,128,0.18);margin-bottom:14px;">
      <div style="font-family:'JetBrains Mono',monospace;font-size:18px;color:#ECECEA;min-height:56px;word-break:break-all;letter-spacing:0.5px;line-height:1.6;">${esc(g.value)||'—'}</div>
      ${g.value?`<div class="mp-strength-bar"><div class="mp-strength-fill" style="width:${st.pct}%;background:${st.color};"></div></div><div style="font-size:11px;color:${st.color};margin-top:6px;font-weight:600;">${st.label}</div>`:''}
      <div style="display:flex;gap:8px;margin-top:14px;">
        <button class="mp-btn-primary" style="flex:1;" onclick="COPY_GEN()">Copiar</button>
        <button onclick="REGEN()" style="width:48px;height:48px;flex-shrink:0;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:13px;cursor:pointer;color:#7b7b82;display:flex;align-items:center;justify-content:center;">${I.refresh}</button>
      </div>
    </div>
    <div class="mp-card" style="margin-bottom:12px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;"><span style="font-size:13px;color:#7b7b82;font-weight:500;">Longitud</span><span style="font-family:'JetBrains Mono',monospace;font-size:16px;font-weight:600;color:#4ade80;">${g.length}</span></div>
      <input type="range" min="6" max="40" value="${g.length}" oninput="S.gen.length=+this.value;REGEN()">
    </div>
    <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:16px;">
      ${checks.map(c=>`<button class="mp-toggle ${g[c.k]?'on':'off'}" onclick="TOGGLE_GEN('${c.k}')"><div class="mp-toggle-check">${g[c.k]?I.checkSm:''}</div>${c.label}</button>`).join('')}
    </div>
    <button class="mp-btn-outline" onclick="USE_GEN()" style="margin-bottom:80px;">Usar en nueva credencial</button>
    ${navHTML('generator')}`;
}
function screenAudit() {
  const {healthScore,weakList,reusedList}=derived();
  const r=52,circ=2*Math.PI*r,dash=((healthScore/100)*circ).toFixed(1);
  const col=healthScore>=80?'#4ade80':healthScore>=50?'#fbbf24':'#f87171';
  const msg=healthScore>=80?'Tu bóveda está bien protegida':healthScore>=50?'Algunas mejoras recomendadas':'Acción requerida';
  return `
    <h1 style="font-size:27px;font-weight:700;color:#ECECEA;letter-spacing:-0.7px;padding-top:10px;margin-bottom:20px;">Salud de seguridad</h1>
    <div style="display:flex;flex-direction:column;align-items:center;margin-bottom:24px;">
      <svg width="148" height="148" viewBox="0 0 148 148">
        <circle cx="74" cy="74" r="${r}" fill="none" stroke="rgba(255,255,255,0.07)" stroke-width="10"/>
        <circle cx="74" cy="74" r="${r}" fill="none" stroke="${col}" stroke-width="10" stroke-dasharray="${dash} ${circ.toFixed(1)}" stroke-linecap="round" transform="rotate(-90 74 74)" style="transition:stroke-dasharray .5s;"/>
        <text x="74" y="70" text-anchor="middle" fill="#ECECEA" font-size="26" font-weight="700" font-family="Space Grotesk,sans-serif">${healthScore}</text>
        <text x="74" y="90" text-anchor="middle" fill="#7b7b82" font-size="12" font-family="Space Grotesk,sans-serif">de 100</text>
      </svg>
      <p style="font-size:14px;color:${col};font-weight:600;margin-top:8px;">${msg}</p>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:24px;">
      <div class="mp-card" style="text-align:center;"><div style="font-size:28px;font-weight:700;color:#f87171;">${weakList.length}</div><div style="font-size:12px;color:#7b7b82;margin-top:4px;">Débiles</div></div>
      <div class="mp-card" style="text-align:center;"><div style="font-size:28px;font-weight:700;color:#fb923c;">${reusedList.length}</div><div style="font-size:12px;color:#7b7b82;margin-top:4px;">Repetidas</div></div>
    </div>
    ${weakList.length?`<div class="mp-section-label">Contraseñas débiles</div>${weakList.map(c=>credRowHTML(c,{label:'Débil',color:'#f87171'})).join('')}`:''}
    ${reusedList.length?`<div class="mp-section-label">Contraseñas repetidas</div>${reusedList.map(c=>credRowHTML(c,{label:'Repetida',color:'#fb923c'})).join('')}`:''}
    ${!weakList.length&&!reusedList.length?`<div style="text-align:center;color:#4ade80;padding:24px 0;font-size:14px;font-weight:600;">Todo en orden ✓</div>`:''}
    ${navHTML('audit')}`;
}
function screenDetail() {
  const c=S.creds.find(x=>x.id===S.selectedId); if(!c){S.screen='vault';render();return'';}
  const st=strength(c.secret);
  const masked=S.revealed?esc(c.secret):'•'.repeat(Math.min((c.secret||'').length,18));
  const tags=c.tags||[];
  return `
    <div style="display:flex;align-items:center;justify-content:space-between;padding-top:10px;margin-bottom:24px;">
      <button class="mp-btn-ghost" onclick="BACK()" style="color:#ECECEA;gap:4px;font-size:15px;font-weight:500;">${I.chevL} Atrás</button>
      <div style="display:flex;gap:12px;">
        <button class="mp-btn-ghost" onclick="TOGGLE_FAV('${c.id}')" style="color:${c.fav?'#4ade80':'#7b7b82'};">${c.fav?I.starFill:I.star}</button>
        <button class="mp-btn-ghost" onclick="OPEN_EDIT('${c.id}')" style="color:#7b7b82;">${I.edit}</button>
      </div>
    </div>
    <div style="display:flex;flex-direction:column;align-items:center;margin-bottom:24px;">
      <div style="width:74px;height:74px;border-radius:22px;background:${getColor(c.platform)};display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:28px;box-shadow:0 4px 14px rgba(0,0,0,0.45);margin-bottom:12px;">${getInitial(c.platform)}</div>
      <h2 style="font-size:23px;font-weight:700;color:#ECECEA;letter-spacing:-0.5px;">${esc(c.platform)}</h2>
      ${c.url?`<p style="font-size:13px;color:#7b7b82;font-family:'JetBrains Mono',monospace;margin-top:4px;">${esc(c.url)}</p>`:''}
    </div>
    <div class="mp-card" style="margin-bottom:12px;">
      <div style="font-size:11px;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;color:#5a5a60;margin-bottom:10px;">${secretLabel(c.type)}</div>
      <div style="display:flex;align-items:center;gap:12px;">
        <span style="flex:1;font-family:'JetBrains Mono',monospace;font-size:15px;color:#ECECEA;word-break:break-all;">${masked}</span>
        <div style="display:flex;gap:8px;flex-shrink:0;">
          <button class="mp-btn-ghost" onclick="TOGGLE_REVEAL()" style="color:#7b7b82;">${S.revealed?I.eyeOff:I.eye}</button>
          <button class="mp-btn-ghost" onclick="COPY_FIELD('${c.id}','secret','Contraseña copiada')" style="color:#7b7b82;">${I.copy}</button>
        </div>
      </div>
      ${c.type==='password'?`<div class="mp-strength-bar"><div class="mp-strength-fill" style="width:${st.pct}%;background:${st.color};"></div></div><div style="font-size:11px;color:${st.color};margin-top:6px;font-weight:600;">${st.label}</div>`:''}
    </div>
    ${c.username?`<button class="mp-copy-row" onclick="COPY_FIELD('${c.id}','username','Usuario copiado')" style="margin-bottom:8px;"><div><div style="font-size:11px;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;color:#5a5a60;margin-bottom:4px;">Usuario</div><div style="font-family:'JetBrains Mono',monospace;font-size:14px;color:#ECECEA;">${esc(c.username)}</div></div><span style="color:#7b7b82;">${I.copy}</span></button>`:''}
    ${c.email?`<button class="mp-copy-row" onclick="COPY_FIELD('${c.id}','email','Correo copiado')" style="margin-bottom:8px;"><div><div style="font-size:11px;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;color:#5a5a60;margin-bottom:4px;">Correo</div><div style="font-family:'JetBrains Mono',monospace;font-size:14px;color:#ECECEA;">${esc(c.email)}</div></div><span style="color:#7b7b82;">${I.copy}</span></button>`:''}
    ${tags.length?`<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px;">${tags.map(t=>`<span class="mp-chip">${esc(t)}</span>`).join('')}</div>`:''}
    ${c.note?`<div class="mp-card" style="margin-bottom:12px;font-size:14px;color:#7b7b82;line-height:1.6;">${esc(c.note)}</div>`:''}
    <div style="display:flex;align-items:center;gap:6px;font-size:12px;color:#5a5a60;margin-bottom:20px;">${I.clock} Última modificación · ${fmtDate(c.updated)}</div>
    <button class="mp-btn-danger" onclick="DEL_CRED('${c.id}')">Eliminar credencial</button>`;
}
function screenForm() {
  const f=S.form; const isEdit=!!S.editingId; const fst=strength(f.secret);
  const tagsStr=Array.isArray(f.tags)?f.tags.join(', '):f.tags;
  return `
    <div style="display:flex;align-items:center;gap:12px;padding-top:10px;margin-bottom:24px;">
      <button class="mp-btn-ghost" onclick="CANCEL_FORM()" style="color:#7b7b82;">${I.chevL}</button>
      <h1 style="font-size:21px;font-weight:700;color:#ECECEA;letter-spacing:-0.5px;">${isEdit?'Editar credencial':'Nueva credencial'}</h1>
    </div>
    <div class="mp-seg"><button class="mp-seg-btn ${f.type==='password'?'on':'off'}" onclick="S.form.type='password';render()">Contraseña</button><button class="mp-seg-btn ${f.type==='token'?'on':'off'}" onclick="S.form.type='token';render()">Token</button><button class="mp-seg-btn ${f.type==='api'?'on':'off'}" onclick="S.form.type='api';render()">API key</button></div>
    <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:16px;">
      <input class="mp-input" type="text" placeholder="Plataforma *" value="${esc(f.platform)}" oninput="S.form.platform=this.value">
      <input class="mp-input mono" type="text" placeholder="Usuario" value="${esc(f.username)}" oninput="S.form.username=this.value">
      <input class="mp-input mono" type="email" placeholder="Correo" value="${esc(f.email)}" oninput="S.form.email=this.value">
      <div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;"><span style="font-size:12px;color:#7b7b82;font-weight:500;">${secretLabel(f.type)} *</span><button onclick="PREFILL_GEN()" style="font-size:12px;color:#4ade80;background:none;border:none;cursor:pointer;font-weight:600;">Generar</button></div>
        <div class="mp-input-wrap"><input class="mp-input mono" type="${S.showPin?'text':'password'}" placeholder="${secretLabel(f.type)}" value="${esc(f.secret)}" oninput="S.form.secret=this.value;UPD_STR()">
        <button class="mp-input-ico" onclick="S.showPin=!S.showPin;render()" style="color:#6b6b72;">${S.showPin?I.eyeOff:I.eye}</button></div>
        <div id="strArea">${f.secret&&f.type==='password'?`<div class="mp-strength-bar"><div class="mp-strength-fill" style="width:${fst.pct}%;background:${fst.color};"></div></div><div style="font-size:11px;color:${fst.color};margin-top:4px;font-weight:600;">${fst.label}</div>`:''}</div>
      </div>
      <input class="mp-input mono" type="url" placeholder="Sitio web" value="${esc(f.url)}" oninput="S.form.url=this.value">
      <input class="mp-input" type="text" placeholder="Etiquetas (separadas por coma)" value="${esc(tagsStr)}" oninput="S.form.tags=this.value">
      <textarea class="mp-input" placeholder="Nota" rows="3" oninput="S.form.note=this.value" style="resize:none;line-height:1.5;">${esc(f.note)}</textarea>
    </div>
    <div style="position:sticky;bottom:0;padding:12px 0 16px;background:linear-gradient(to top,#0a0a0c 70%,transparent);">
      <button class="mp-btn-primary" onclick="SAVE_CRED()">${I.check} Guardar credencial</button>
    </div>`;
}

// ── RENDER ────────────────────────────────────────────
function render() {
  const app=document.getElementById('app');
  let inner='';
  if(S.locked||S.authStep!=='done') { inner=screenLock(); }
  else {
    const screens={vault:screenVault,categories:screenCategories,generator:screenGenerator,audit:screenAudit,detail:screenDetail,add:screenForm,edit:screenForm};
    inner=(screens[S.screen]||screenVault)();
  }
  app.innerHTML=`<div class="mp-page"><div class="mp-phone">${statusBarHTML()}<div class="mp-content"><div class="mp-screen" data-scroll>${inner}</div>${S.toast?`<div class="mp-toast"><span style="color:#4ade80;">${I.check}</span>${esc(S.toast)}</div>`:''}</div></div></div>`;

  // Restaurar pin
  const pinEl=document.getElementById('pinInput'); if(pinEl){pinEl.value=S.pin;pinEl.focus();}

  // Bind TOTP inputs
  if(S.authStep==='totp-verify')       bindTotpInput('totp-main',    code=>TOTP_VERIFY(code));
  if(S.authStep==='totp-setup-confirm') bindTotpInput('totp-confirm', code=>TOTP_SETUP_CONFIRM(code));
  if(S.authStep==='recovery-1')         bindTotpInput('totp-rec1',    code=>RECOVERY_CODE1(code));
  if(S.authStep==='recovery-2')         bindTotpInput('totp-rec2',    code=>RECOVERY_CODE2(code));

  // Generar QR client-side (qrcodejs desde CDN, sin dependencia de APIs externas)
  if(S.authStep==='totp-setup-scan' && S.totpSecret) {
    const qrEl = document.getElementById('qr-render');
    if(qrEl && typeof QRCode !== 'undefined') {
      qrEl.innerHTML = '';
      new QRCode(qrEl, {
        text: `otpauth://totp/MyPass?secret=${S.totpSecret}&issuer=MyPass&algorithm=SHA1&digits=6&period=30`,
        width: 168, height: 168, colorDark: '#000000', colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.M
      });
    }
  }

  // Countdown tick
  if(S.authStep==='recovery-2') startCountdown();

  // Credential row clicks
  app.querySelectorAll('.mp-cred-row').forEach(btn=>{
    btn.addEventListener('mouseenter',()=>btn.style.background='rgba(255,255,255,0.045)');
    btn.addEventListener('mouseleave',()=>btn.style.background='transparent');
    btn.addEventListener('click',()=>OPEN_DETAIL(btn.dataset.id));
  });
}

function startCountdown() {
  clearInterval(S.countdownTimer);
  S.countdownSec=secondsLeft();
  S.countdownTimer=setInterval(()=>{
    S.countdownSec=secondsLeft();
    const el=document.getElementById('countdown');
    if(el){ el.textContent=`${S.countdownSec}s`; el.className='mp-countdown'+(S.countdownSec<=10?' urgent':''); }
  },1000);
}

// ── ACCIONES ──────────────────────────────────────────
window.S=S;
window.render=render;
window.UPD_STR=function(){const el=document.getElementById('strArea');if(!el)return;const inp=el.closest('div').querySelector('input');if(!inp)return;const s=inp.value;S.form.secret=s;if(s&&S.form.type==='password'){const st=strength(s);el.innerHTML=`<div class="mp-strength-bar"><div class="mp-strength-fill" style="width:${st.pct}%;background:${st.color};"></div></div><div style="font-size:11px;color:${st.color};margin-top:4px;font-weight:600;">${st.label}</div>`;}else el.innerHTML='';};

window.GO=function(sc){S.screen=sc;S.query='';S.selectedId=null;S.revealed=false;render();};
window.LOCK=function(){clearInterval(S.countdownTimer);S.locked=true;S.cryptoKey=null;S.creds=[];S.pin='';S.authStep='password';S.screen='vault';render();};
window.TOAST=function(msg){S.toast=msg;render();setTimeout(()=>{S.toast=null;render();},1700);};
window.OPEN_DETAIL=function(id){S.selectedId=id;S.revealed=false;S.screen='detail';render();};
window.OPEN_ADD=function(){S.editingId=null;S.showPin=false;S.form={platform:'',type:'password',username:'',email:'',secret:'',url:'',tags:'',note:''};S.screen='add';render();};
window.OPEN_EDIT=function(id){const c=S.creds.find(x=>x.id===id);if(!c)return;S.editingId=id;S.showPin=false;S.form={...c,tags:(c.tags||[]).join(', ')};S.screen='edit';render();};
window.CANCEL_FORM=function(){S.screen=S.editingId?'detail':'vault';render();};
window.BACK=function(){S.screen='vault';S.selectedId=null;render();};
window.TOGGLE_REVEAL=function(){S.revealed=!S.revealed;render();};
window.TOGGLE_FAV=async function(id){S.creds=S.creds.map(c=>c.id===id?{...c,fav:!c.fav}:c);await persist();render();};
window.DEL_CRED=async function(id){if(!confirm('¿Eliminar esta credencial?'))return;S.creds=S.creds.filter(c=>c.id!==id);S.screen='vault';await persist();render();TOAST('Credencial eliminada');};
window.COPY_FIELD=function(id,field,msg){const c=S.creds.find(x=>x.id===id);if(!c)return;navigator.clipboard.writeText(c[field]).then(()=>TOAST(msg)).catch(()=>TOAST('No se pudo copiar'));};
window.COPY_GEN=function(){navigator.clipboard.writeText(S.gen.value).then(()=>TOAST('Contraseña copiada')).catch(()=>TOAST('Error al copiar'));};
window.REGEN=function(){S.gen.value=genPassword(S.gen);render();};
window.TOGGLE_GEN=function(k){const active=['upper','lower','numbers','symbols'].filter(x=>S.gen[x]);if(active.length===1&&active[0]===k)return;S.gen[k]=!S.gen[k];REGEN();};
window.USE_GEN=function(){S.editingId=null;S.showPin=false;S.form={platform:'',type:'password',username:'',email:'',secret:S.gen.value,url:'',tags:'',note:''};S.screen='add';render();};
window.PREFILL_GEN=function(){S.form.secret=genPassword(S.gen);render();};
window.SAVE_CRED=async function(){const f=S.form;if(!f.platform.trim()||!f.secret.trim()){TOAST('Completa plataforma y secreto');return;}const tags=(typeof f.tags==='string'?f.tags:f.tags.join(',')).split(',').map(t=>t.trim()).filter(Boolean);if(S.editingId){const id=S.editingId;S.creds=S.creds.map(c=>c.id===id?{...c,...f,tags,updated:new Date().toISOString()}:c);S.screen='detail';}else{S.creds=[...S.creds,{id:uid(),...f,tags,fav:false,updated:new Date().toISOString()}];S.screen='vault';}await persist();render();TOAST(S.editingId?'Cambios guardados':'Credencial guardada');};

// ── UNLOCK ────────────────────────────────────────────
window.UNLOCK=async function(){
  if(!S.pin.trim())return;
  S.loading=true;render();
  try {
    const row=await loadVaultRow();
    if(!row){
      // Primera vez → crear bóveda
      const salt=crypto.getRandomValues(new Uint8Array(16));
      S.saltB64=b64(salt);
      S.cryptoKey=await deriveKey(S.pin,salt);
      S.creds=[];
      // Iniciar setup TOTP
      S.totpSecret=generateSecret();
      S.loading=false;
      S.authStep='totp-setup-scan';
      render();
    } else if(!row.totp_secret){
      // Vault existe pero sin TOTP (legacy) → entrar directo y pedir setup
      const salt=fromB64(row.salt);
      S.saltB64=row.salt;
      const key=await deriveKey(S.pin,salt);
      const creds=await decryptVault(key,row.iv,row.encrypted_data);
      S.cryptoKey=key; S.creds=creds;
      S.totpSecret=generateSecret();
      S.loading=false;
      S.authStep='totp-setup-scan';
      render();
    } else {
      // Vault existe con TOTP → verificar contraseña y pedir código
      const salt=fromB64(row.salt);
      S.saltB64=row.salt;
      const key=await deriveKey(S.pin,salt);
      // Intenta descifrar para verificar contraseña
      await decryptVault(key,row.iv,row.encrypted_data);
      S.cryptoKey=key;
      // Contraseña ok → pedir TOTP
      S.loading=false;
      S.authStep='totp-verify';
      render();
    }
  } catch {
    S.loading=false;S.pin='';render();TOAST('Contraseña incorrecta');
  }
};

// ── TOTP VERIFY (login 2FA) ───────────────────────────
window.TOTP_VERIFY=async function(code){
  S.loading=true;render();
  try {
    const row=await loadVaultRow();
    const ok=await verifyCode(row.totp_secret,code);
    if(!ok){S.loading=false;render();TOAST('Código incorrecto');return;}
    // Cargar credenciales
    const creds=await decryptVault(S.cryptoKey,row.iv,row.encrypted_data);
    S.creds=creds;S.locked=false;S.authStep='done';S.loading=false;render();
    TOAST('Bóveda desbloqueada ✓');
  } catch { S.loading=false;render();TOAST('Error al verificar'); }
};

// ── TOTP SETUP ────────────────────────────────────────
window.TOTP_SETUP_CONFIRM=async function(code){
  S.loading=true;render();
  const ok=await verifyCode(S.totpSecret,code);
  if(!ok){S.loading=false;render();TOAST('Código incorrecto, intenta de nuevo');return;}
  try {
    // Generar recovery blob
    const recoveryKey=await deriveRecoveryKey(S.totpSecret);
    const { blob, iv: riv }=await encryptKeyForRecovery(S.cryptoKey,recoveryKey);
    // Guardar vault + totp_secret + recovery
    const e=await encryptVault(S.cryptoKey,S.creds);
    await saveVaultRow({ encrypted_data:e.data, iv:e.iv, salt:S.saltB64, totp_secret:S.totpSecret, recovery_blob:blob, recovery_iv:riv });
    S.locked=false;S.authStep='done';S.loading=false;S.totpSecret=null;render();
    TOAST('Google Authenticator activado ✓');
  } catch(e){ S.loading=false;render();TOAST('Error al guardar'); }
};

// ── RECUPERACIÓN ──────────────────────────────────────
window.RECOVERY_CODE1=async function(code){
  S.loading=true;render();
  try {
    const row=await loadVaultRow();
    if(!row?.totp_secret){S.loading=false;render();TOAST('No hay autenticador configurado');return;}
    const ok=await verifyCode(row.totp_secret,code);
    if(!ok){S.loading=false;render();TOAST('Código incorrecto');return;}
    S.totpCode=code;
    clearInterval(S.countdownTimer);
    S.loading=false;S.authStep='recovery-2';render();
  } catch { S.loading=false;render();TOAST('Error'); }
};

window.RECOVERY_CODE2=async function(code){
  if(code===S.totpCode){TOAST('Debes esperar al siguiente código (30 seg)');return;}
  S.loading=true;render();
  try {
    const row=await loadVaultRow();
    const ok=await verifyCode(row.totp_secret,code);
    if(!ok){S.loading=false;render();TOAST('Código incorrecto');return;}
    // Descifrar vault key con recovery key
    const recoveryKey=await deriveRecoveryKey(row.totp_secret);
    const vaultKey=await decryptKeyFromRecovery(row.recovery_blob,row.recovery_iv,recoveryKey);
    S.recoveryKey=vaultKey;
    clearInterval(S.countdownTimer);
    S.loading=false;S.authStep='recovery-new-pwd';render();
  } catch { S.loading=false;render();TOAST('Error al recuperar'); }
};

window.RECOVERY_SAVE=async function(){
  if(!S.recoveryNewPwd?.trim()){TOAST('Escribe tu nueva contraseña');return;}
  S.loading=true;render();
  try {
    const row=await loadVaultRow();
    // Descifrar creds con recovery key
    const creds=await decryptVault(S.recoveryKey,row.iv,row.encrypted_data);
    // Nueva clave maestra
    const salt=crypto.getRandomValues(new Uint8Array(16));
    S.saltB64=b64(salt);
    S.cryptoKey=await deriveKey(S.recoveryNewPwd,salt);
    S.creds=creds;
    // Nuevo recovery blob con la nueva clave
    const recoveryKey=await deriveRecoveryKey(row.totp_secret);
    const { blob, iv:riv }=await encryptKeyForRecovery(S.cryptoKey,recoveryKey);
    const e=await encryptVault(S.cryptoKey,creds);
    await saveVaultRow({ encrypted_data:e.data, iv:e.iv, salt:S.saltB64, totp_secret:row.totp_secret, recovery_blob:blob, recovery_iv:riv });
    S.recoveryKey=null;S.recoveryNewPwd='';S.locked=false;S.authStep='done';S.loading=false;render();
    TOAST('Contraseña restablecida ✓');
  } catch { S.loading=false;render();TOAST('Error al guardar'); }
};

// ── INIT ──────────────────────────────────────────────
S.gen.value=genPassword(S.gen);
render();
