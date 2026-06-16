// =====================================================
// CredRow — componente de fila de credencial
// Espejo del CredRow.dc.html del diseño
// =====================================================

const PALETTE = ['#2563eb','#db2777','#dc2626','#ea580c','#16a34a','#0ea5e9','#6366f1','#0d9488','#7c3aed','#0a66c2','#e11d48','#0891b2'];

export function getColor(platform) {
  let h = 0;
  for (const ch of (platform || '')) h = (h * 31 + ch.charCodeAt(0)) & 0x7fffffff;
  return PALETTE[h % PALETTE.length];
}

export function getInitial(platform) {
  return ((platform || '?')[0]).toUpperCase();
}

export function typeBadge(type) {
  return type === 'token' ? 'TOKEN' : type === 'api' ? 'API' : '';
}

/**
 * Renderiza el HTML de una fila de credencial.
 * @param {object} c - credencial
 * @param {object} [badge] - { label, color } opcional
 */
export function credRowHTML(c, badge = null) {
  const color   = getColor(c.platform);
  const initial = getInitial(c.platform);
  const sub     = c.username || c.email || c.url || '—';
  const typeTag = typeBadge(c.type);
  const favSVG  = c.fav
    ? `<svg width="13" height="13" viewBox="0 0 24 24" fill="#4ade80" stroke="none" style="flex:none;"><path d="M12 2l2.9 6.2 6.8.8-5 4.6 1.3 6.7L12 17.8 5.9 20.3 7.2 13.6l-5-4.6 6.8-.8z"/></svg>`
    : '';

  const badgeHTML = badge
    ? `<span style="flex:none;font-size:10px;font-weight:600;color:${badge.color};background:rgba(255,255,255,0.05);border-radius:6px;padding:3px 8px;">${badge.label}</span>`
    : '';

  return `
    <button class="mp-cred-row" data-id="${c.id}" style="display:flex;align-items:center;gap:14px;width:100%;text-align:left;background:transparent;border:none;border-radius:15px;padding:10px 11px;cursor:pointer;font-family:'Space Grotesk',sans-serif;">
      <div style="flex:none;width:46px;height:46px;border-radius:14px;background:${color};display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:18px;box-shadow:0 4px 14px rgba(0,0,0,0.45);">${initial}</div>
      <div style="flex:1;min-width:0;">
        <div style="display:flex;align-items:center;gap:7px;">
          <span style="font-size:15.5px;font-weight:600;color:#ECECEA;letter-spacing:-0.2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(c.platform)}</span>
          ${typeTag ? `<span style="flex:none;font-size:9px;font-weight:700;letter-spacing:0.7px;color:#9a9aa2;border:1px solid rgba(255,255,255,0.12);border-radius:5px;padding:1px 5px;">${typeTag}</span>` : ''}
          ${favSVG}
        </div>
        <div style="font-size:12.5px;color:#7b7b82;font-family:'JetBrains Mono',monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:3px;">${esc(sub)}</div>
      </div>
      ${badgeHTML}
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#3f3f46" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex:none;"><polyline points="9 6 15 12 9 18"/></svg>
    </button>`;
}

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
