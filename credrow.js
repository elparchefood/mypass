// =====================================================
// credrow.js — Fila de credencial + plataformas conocidas
// =====================================================

// ── Plataformas conocidas ─────────────────────────────
export const PLATFORMS = [
  { name:'Facebook',   domain:'facebook.com',   color:'#1877F2' },
  { name:'Instagram',  domain:'instagram.com',  color:'#C13584' },
  { name:'TikTok',     domain:'tiktok.com',     color:'#111111' },
  { name:'Google',     domain:'google.com',     color:'#4285F4' },
  { name:'YouTube',    domain:'youtube.com',    color:'#FF0000' },
  { name:'GitHub',     domain:'github.com',     color:'#24292E' },
  { name:'Supabase',   domain:'supabase.com',   color:'#3ECF8E' },
  { name:'WhatsApp',   domain:'whatsapp.com',   color:'#25D366' },
  { name:'Gmail',      domain:'gmail.com',      color:'#EA4335' },
  { name:'X / Twitter',domain:'x.com',          color:'#000000' },
  { name:'LinkedIn',   domain:'linkedin.com',   color:'#0A66C2' },
  { name:'Discord',    domain:'discord.com',    color:'#5865F2' },
  { name:'Spotify',    domain:'spotify.com',    color:'#1DB954' },
  { name:'Netflix',    domain:'netflix.com',    color:'#E50914' },
  { name:'Amazon',     domain:'amazon.com',     color:'#FF9900' },
  { name:'Apple',      domain:'apple.com',      color:'#555555' },
  { name:'Microsoft',  domain:'microsoft.com',  color:'#00A4EF' },
  { name:'Stripe',     domain:'stripe.com',     color:'#635BFF' },
  { name:'PayPal',     domain:'paypal.com',     color:'#003087' },
  { name:'Slack',      domain:'slack.com',      color:'#4A154B' },
  { name:'Notion',     domain:'notion.so',      color:'#000000' },
  { name:'Figma',      domain:'figma.com',      color:'#F24E1E' },
  { name:'Shopify',    domain:'shopify.com',    color:'#96BF48' },
  { name:'Porkbun',    domain:'porkbun.com',    color:'#EF7C37' },
  { name:'Canva',      domain:'canva.com',      color:'#00C4CC' },
  { name:'Dropbox',    domain:'dropbox.com',    color:'#0061FF' },
];

export function getPlatform(name) {
  if (!name) return null;
  const n = name.toLowerCase().trim();
  return PLATFORMS.find(p => p.name.toLowerCase() === n) || null;
}

// ── Avatar de plataforma ──────────────────────────────
export function platformAvatarHTML(name, size = 48, radius = 16) {
  const p = getPlatform(name);
  const iconSize = Math.round(size * 0.55);
  if (p) {
    return `<div style="width:${size}px;height:${size}px;border-radius:${radius}px;background:${p.color};display:flex;align-items:center;justify-content:center;flex-shrink:0;overflow:hidden;">
      <img src="https://www.google.com/s2/favicons?domain=${p.domain}&sz=64" width="${iconSize}" height="${iconSize}" style="object-fit:contain;" onerror="this.parentNode.innerHTML='<span style=color:#fff;font-weight:700;font-size:${Math.round(size*0.4)}px>${getInitial(name)}</span>'">
    </div>`;
  }
  return `<div style="width:${size}px;height:${size}px;border-radius:${radius}px;background:${getColor(name)};display:flex;align-items:center;justify-content:center;flex-shrink:0;font-weight:700;font-size:${Math.round(size*0.4)}px;color:#fff;">${getInitial(name)}</div>`;
}

// ── Helpers de color/inicial (fallback para plataformas custom) ──
const PALETTE = ['#f43f5e','#ec4899','#a855f7','#8b5cf6','#6366f1','#3b82f6','#0ea5e9','#06b6d4','#14b8a6','#22c55e','#84cc16','#eab308','#f97316','#ef4444'];

export function getColor(name) {
  if (!name) return PALETTE[0];
  let h = 0; for (const c of name) h = (h * 31 + c.charCodeAt(0)) & 0xffff;
  return PALETTE[h % PALETTE.length];
}

export function getInitial(name) {
  return (name || '?')[0].toUpperCase();
}

// ── Badge de tipo ─────────────────────────────────────
export function typeBadge(type) {
  if (type === 'token') return `<span style="font-size:10px;font-weight:600;color:#fbbf24;background:rgba(251,191,36,0.12);border:1px solid rgba(251,191,36,0.25);border-radius:5px;padding:2px 6px;letter-spacing:0.3px;">TOKEN</span>`;
  if (type === 'api')   return `<span style="font-size:10px;font-weight:600;color:#a78bfa;background:rgba(167,139,250,0.12);border:1px solid rgba(167,139,250,0.25);border-radius:5px;padding:2px 6px;letter-spacing:0.3px;">API</span>`;
  return '';
}

// ── Fila de credencial ────────────────────────────────
export function credRowHTML(c, badge) {
  const tags = (c.tags || []).slice(0, 2);
  const sub  = c.username || c.email || '';
  return `<button class="mp-cred-row" data-id="${c.id}" style="width:100%;display:flex;align-items:center;gap:14px;padding:12px 4px;background:transparent;border:none;cursor:pointer;text-align:left;border-radius:14px;transition:background .15s;">
    ${platformAvatarHTML(c.platform, 48, 16)}
    <div style="flex:1;min-width:0;">
      <div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;">
        <span style="font-size:15px;font-weight:600;color:#ECECEA;letter-spacing:-0.2px;">${esc(c.platform)}</span>
        ${typeBadge(c.type)}
        ${badge ? `<span style="font-size:10px;font-weight:600;color:${badge.color};background:${badge.color}20;border:1px solid ${badge.color}40;border-radius:5px;padding:2px 6px;">${badge.label}</span>` : ''}
        ${c.fav ? `<span style="color:#4ade80;font-size:13px;">★</span>` : ''}
      </div>
      <div style="display:flex;align-items:center;gap:8px;margin-top:3px;flex-wrap:wrap;">
        ${sub ? `<span style="font-size:12.5px;color:#7b7b82;font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px;">${esc(sub)}</span>` : ''}
        ${tags.map(t => `<span style="font-size:10.5px;color:#4d4d54;background:rgba(255,255,255,0.05);border-radius:5px;padding:1px 6px;">${esc(t)}</span>`).join('')}
      </div>
    </div>
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#3a3a40" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
  </button>`;
}

function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
