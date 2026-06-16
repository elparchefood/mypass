# My Pass

Gestor de contraseñas personal con cifrado AES-256-GCM de extremo a extremo.

**URL:** https://elparchefood.github.io/mypass/  
**Repo:** https://github.com/elparchefood/mypass

## ⚠️ Proyecto independiente

Este proyecto NO forma parte del sistema POS "El Parche Food" / Cobra POS.  
Es una herramienta personal de Sergio para gestionar sus contraseñas.

- Supabase: mismo proyecto (`tblujfduscslxjmrjbdr`) pero tabla exclusiva `mypass_vault`
- No comparte código, rutas ni módulos con el POS

## Archivos

| Archivo | Rol |
|---|---|
| `index.html` | Shell HTML — carga CSS y JS |
| `mypass.css` | Todos los estilos |
| `mypass.js` | Lógica principal (ES module) |
| `credrow.js` | Componente CredRow — importado por mypass.js |

## Seguridad

- Contraseña maestra → PBKDF2 (100 000 iteraciones, SHA-256) → clave AES-256-GCM
- Los datos viajan y se almacenan **siempre cifrados** — Supabase nunca ve texto plano
- Arquitectura de conocimiento cero: la clave nunca sale del navegador
