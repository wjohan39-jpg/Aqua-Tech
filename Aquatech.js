/* ═══════════════════════════════════════════════════════
   AQUAGESTIÓN · aquagestion.js
   Sección 1: Navegación + Sidebar + Inicialización base
   ═══════════════════════════════════════════════════════ */

'use strict';

// Defensa anti-clickjacking (capa JS — complementa X-Frame-Options y CSP frame-ancestors).
// Intenta redirigir el frame padre; si el iframe está sandboxed y bloquea la navegación,
// oculta el body como último recurso para que no haya superficie atacable.
(function guardFrame() {
  if (window.top === window.self) return;
  try {
    window.top.location = window.self.location;
  } catch (_) {
    document.documentElement.style.display = 'none';
  }
}());

function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Convierte un valor leído de localStorage a número seguro para innerHTML.
// Cualquier valor no numérico (incluyendo strings con HTML) retorna '–'.
function _safeNum(v, fix) {
  const n = Number(v);
  if (!isFinite(n)) return '–';
  return fix !== undefined ? n.toFixed(fix) : String(n);
}

// Valida que un valor sea un data URI de imagen base64 válido antes de usarlo como src.
// Acepta JPEG (nuevas fotos) y PNG (fotos guardadas antes de la migración a JPEG).
// Previene inyección de atributo y URLs externas provenientes de localStorage tamperado.
function _safePhotoSrc(v) {
  if (typeof v !== 'string') return '';
  if (v.startsWith('data:image/jpeg;base64,') || v.startsWith('data:image/png;base64,')) return v;
  return '';
}

// ── INTEGRIDAD DE ALMACENAMIENTO (HMAC-SHA256 + IndexedDB) ───────────────
// CryptoKey no-extractable en IndexedDB — protege contra edición directa
// de localStorage entre sesiones (DevTools, acceso físico al dispositivo).
const _INTEGRITY = (() => {
  const DB    = 'brazada_integrity_v1';
  const STORE = 'keys';
  const KID   = 'hmac_k';
  let _cache  = null;

  function _openDb() {
    return new Promise((res, rej) => {
      const r = indexedDB.open(DB, 1);
      r.onupgradeneeded = e => e.target.result.createObjectStore(STORE);
      r.onsuccess = e => res(e.target.result);
      r.onerror   = e => rej(e.target.error);
    });
  }

  async function _getKey() {
    if (_cache) return _cache;
    const db = await _openDb();
    return new Promise((res, rej) => {
      const req = db.transaction(STORE, 'readwrite').objectStore(STORE).get(KID);
      req.onsuccess = async () => {
        if (req.result) { _cache = req.result; return res(_cache); }
        const k = await crypto.subtle.generateKey(
          { name: 'HMAC', hash: 'SHA-256' },
          false,                        // no-extractable: el material de clave nunca sale de IDB
          ['sign', 'verify']
        );
        const tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).put(k, KID);
        tx.oncomplete = () => { _cache = k; res(k); };
        tx.onerror    = e => rej(e.target.error);
      };
      req.onerror = e => rej(e.target.error);
    });
  }

  async function sign(text) {
    const k   = await _getKey();
    const buf = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(text));
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }

  async function verify(text, b64) {
    try {
      const k      = await _getKey();
      const sigBuf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
      return await crypto.subtle.verify('HMAC', k, sigBuf, new TextEncoder().encode(text));
    } catch { return false; }
  }

  return { sign, verify };
})();

// ── AUTENTICACIÓN POR PIN (PBKDF2 · SHA-256) ─────────────────────────────
// Estado de sesión encapsulado — no accesible como variable global directa.
const _PIN = (() => {
  const KEY   = 'aqua_pin';
  const ITERS = 600_000;   // OWASP 2024: mínimo 600k para PBKDF2-HMAC-SHA-256
  const HASH  = 'SHA-256';
  const BITS  = 256;

  // Estado de sesión privado
  let _unlocked    = false;
  let _attempts    = 0;
  let _lockedUntil = 0;

  const _SS_KEY = '_pin_state';
  function _loadAttemptState() {
    try {
      const s = JSON.parse(sessionStorage.getItem(_SS_KEY) || '{}');
      _attempts    = typeof s.attempts    === 'number' ? s.attempts    : 0;
      _lockedUntil = typeof s.lockedUntil === 'number' ? s.lockedUntil : 0;
    } catch { _attempts = 0; _lockedUntil = 0; }
  }
  function _saveAttemptState() {
    sessionStorage.setItem(_SS_KEY, JSON.stringify({ attempts: _attempts, lockedUntil: _lockedUntil }));
  }
  _loadAttemptState();

  function _b64(buf)  { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
  function _unb64(s)  { return Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer; }

  async function _derive(pin, salt) {
    const mat = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(pin), { name: 'PBKDF2' }, false, ['deriveBits']
    );
    return crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: ITERS, hash: HASH }, mat, BITS
    );
  }

  async function set(pin) {
    const salt = crypto.getRandomValues(new Uint8Array(16)).buffer;
    const hash = await _derive(pin, salt);
    localStorage.setItem(KEY, JSON.stringify({ salt: _b64(salt), hash: _b64(hash) }));
  }

  async function verify(pin) {
    const stored = JSON.parse(localStorage.getItem(KEY) || 'null');
    if (!stored) return false;
    const actual = await _derive(pin, _unb64(stored.salt));
    const a = new Uint8Array(actual);
    const b = new Uint8Array(_unb64(stored.hash));
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function exists() { return !!localStorage.getItem(KEY); }
  function remove() { localStorage.removeItem(KEY); }

  // Interfaz de sesión — acceso controlado al estado privado
  function unlock()       { _unlocked = true; _attempts = 0; _lockedUntil = 0; _saveAttemptState(); }
  function lock()         { _unlocked = false; }
  function addAttempt()   { ++_attempts; _saveAttemptState(); return _attempts; }
  function setLockout(ms) { _lockedUntil = Date.now() + ms; _saveAttemptState(); }
  function remainingSecs(){ return Math.max(0, Math.ceil((_lockedUntil - Date.now()) / 1000)); }

  return {
    set, verify, exists, remove,
    unlock, lock, addAttempt, setLockout, remainingSecs,
    get unlocked()  { return _unlocked;  },
    get attempts()  { return _attempts;  },
  };
})();

function _pinSwitchView(view) {
  ['pinViewSetup', 'pinViewUnlock', 'pinViewChange'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.hidden = (el.id !== view);
  });
  const input = document.querySelector(`#${view} input`);
  if (input) setTimeout(() => input.focus(), 60);
}

function _pinShowOverlay(view) {
  _pinClearErrors();
  _pinSwitchView(view);
  const overlay = document.getElementById('pinOverlay');
  if (overlay) overlay.hidden = false;
}

function _pinHideOverlay() {
  const overlay = document.getElementById('pinOverlay');
  if (overlay) overlay.hidden = true;
  _pinClearErrors();
  ['pinSetupNew','pinSetupConfirm','pinUnlockInput',
   'pinChangeOld','pinChangeNew','pinChangeConfirm'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
}

function _pinClearErrors() {
  ['pinSetupError','pinUnlockError','pinChangeError'].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.hidden = true; el.textContent = ''; }
  });
}

function _pinSetError(errId, msg) {
  const el = document.getElementById(errId);
  if (el) { el.textContent = msg; el.hidden = false; }
  const card = document.querySelector('.pin-card');
  if (card) {
    card.classList.remove('pin-shake');
    void card.offsetWidth;
    card.classList.add('pin-shake');
  }
}

function _pinValidate(pin) {
  if (!pin || pin.length < 4) return 'El PIN debe tener al menos 4 dígitos.';
  if (!/^\d+$/.test(pin))    return 'El PIN solo puede contener dígitos.';
  const WEAK = ['0000','1111','2222','3333','4444','5555','6666','7777','8888','9999',
                '1234','4321','0123','9876','1230','2345','3456','4567','5678','6789'];
  if (WEAK.includes(pin.slice(0, 4))) return 'PIN demasiado predecible. Elige una combinación menos común.';
  return null;
}

async function _pinHandleCreate() {
  const newPin  = (document.getElementById('pinSetupNew')?.value || '').trim();
  const confirm = (document.getElementById('pinSetupConfirm')?.value || '').trim();
  const err = _pinValidate(newPin);
  if (err)                 { _pinSetError('pinSetupError', err); return; }
  if (newPin !== confirm)  { _pinSetError('pinSetupError', 'Los PINs no coinciden.'); return; }
  const btn = document.getElementById('btnPinCreate');
  if (btn) { btn.disabled = true; btn.textContent = 'Guardando…'; }
  await _PIN.set(newPin);
  _PIN.unlock();
  _pinHideOverlay();
  sectionInit(APP.currentSection);
  if (btn) { btn.disabled = false; btn.textContent = 'Crear PIN'; }
  showToast('PIN creado. La app quedará protegida al recargar.', 'success');
}

async function _pinHandleUnlock() {
  // Rate limiting: bloqueo progresivo tras fallos consecutivos
  const remaining = _PIN.remainingSecs();
  if (remaining > 0) {
    _pinSetError('pinUnlockError', `Demasiados intentos fallidos. Espera ${remaining} segundo${remaining === 1 ? '' : 's'}.`);
    return;
  }

  const pin = (document.getElementById('pinUnlockInput')?.value || '').trim();
  if (!pin) { _pinSetError('pinUnlockError', 'Ingresa tu PIN.'); return; }

  const btn = document.getElementById('btnPinUnlock');
  if (btn) { btn.disabled = true; btn.textContent = 'Verificando…'; }

  const ok = await _PIN.verify(pin);

  if (ok) {
    _PIN.unlock();
    _pinHideOverlay();
    sectionInit(APP.currentSection);
  } else {
    const attempts = _PIN.addAttempt();
    // Bloqueo a partir del 5.º fallo: 30 s · 60 s · 120 s · 240 s · 300 s (cap)
    if (attempts >= 5) {
      const lockMs   = Math.min(30_000 * Math.pow(2, attempts - 5), 300_000);
      _PIN.setLockout(lockMs);
      const lockSecs = Math.ceil(lockMs / 1000);
      _pinSetError('pinUnlockError', `PIN incorrecto. Acceso bloqueado ${lockSecs} segundo${lockSecs === 1 ? '' : 's'}.`);
    } else {
      const left = 5 - attempts;
      _pinSetError('pinUnlockError', `PIN incorrecto. ${left} intento${left === 1 ? '' : 's'} restante${left === 1 ? '' : 's'} antes del bloqueo.`);
    }
    const input = document.getElementById('pinUnlockInput');
    if (input) { input.value = ''; input.focus(); }
  }

  if (btn) { btn.disabled = false; btn.textContent = 'Desbloquear'; }
}

async function _pinHandleChange() {
  const remaining = _PIN.remainingSecs();
  if (remaining > 0) {
    _pinSetError('pinChangeError', `Demasiados intentos fallidos. Espera ${remaining} segundo${remaining === 1 ? '' : 's'}.`);
    return;
  }
  const oldPin  = (document.getElementById('pinChangeOld')?.value || '').trim();
  const newPin  = (document.getElementById('pinChangeNew')?.value || '').trim();
  const confirm = (document.getElementById('pinChangeConfirm')?.value || '').trim();
  if (!oldPin)              { _pinSetError('pinChangeError', 'Ingresa tu PIN actual.'); return; }
  const err = _pinValidate(newPin);
  if (err)                  { _pinSetError('pinChangeError', err); return; }
  if (newPin !== confirm)   { _pinSetError('pinChangeError', 'Los PINs nuevos no coinciden.'); return; }
  const btn = document.getElementById('btnPinChangeSave');
  if (btn) { btn.disabled = true; btn.textContent = 'Guardando…'; }
  const ok = await _PIN.verify(oldPin);
  if (!ok) {
    const attempts = _PIN.addAttempt();
    if (attempts >= 5) {
      const lockMs  = Math.min(30_000 * Math.pow(2, attempts - 5), 300_000);
      _PIN.setLockout(lockMs);
      const lockSecs = Math.ceil(lockMs / 1000);
      _pinSetError('pinChangeError', `PIN incorrecto. Acceso bloqueado ${lockSecs} segundo${lockSecs === 1 ? '' : 's'}.`);
    } else {
      const left = 5 - attempts;
      _pinSetError('pinChangeError', `PIN actual incorrecto. ${left} intento${left === 1 ? '' : 's'} restante${left === 1 ? '' : 's'}.`);
    }
    if (btn) { btn.disabled = false; btn.textContent = 'Guardar'; }
    return;
  }
  await _PIN.set(newPin);
  _PIN.unlock();
  _pinHideOverlay();
  if (btn) { btn.disabled = false; btn.textContent = 'Guardar'; }
  showToast('PIN actualizado correctamente.', 'success');
}

function _pinHandleReset() {
  showConfirm(
    '¿Restablecer PIN? Se borrarán TODOS los datos de la aplicación (bitácora, AFR, configuración). Esta acción no se puede deshacer.',
    () => {
      localStorage.clear();
      sessionStorage.clear();
      indexedDB.deleteDatabase('brazada_integrity_v1');
      if ('caches' in self) {
        caches.keys().then(keys => Promise.all(keys.map(k => caches.delete(k))));
      }
      location.reload();
    }
  );
}

// Guard de sesión: retorna false y muestra unlock si el PIN existe y la sesión no está desbloqueada.
// Usar al inicio de cualquier función que acceda a datos sensibles de localStorage.
function _requireUnlocked() {
  if (_PIN.exists() && !_PIN.unlocked) {
    _pinShowOverlay('pinViewUnlock');
    return false;
  }
  return true;
}

function lockApp() {
  if (!_PIN.exists()) { showToast('No hay PIN configurado.', 'warning'); return; }
  _PIN.lock();
  ['aqua_irapi_result','aqua_irapi_sliders',
   'aqua_lsi_result','aqua_lsi_fields',
   'aqua_calc_medicion'].forEach(k => sessionStorage.removeItem(k));
  _pinShowOverlay('pinViewUnlock');
}

function openChangePinView() {
  _pinShowOverlay(_PIN.exists() ? 'pinViewChange' : 'pinViewSetup');
}

function _pinInit() {
  if (!_PIN.exists()) {
    _pinShowOverlay('pinViewSetup');
  } else {
    _pinShowOverlay('pinViewUnlock');
  }
}

// Guarda json en localStorage y, en paralelo, firma y persiste el HMAC.
// La escritura es sincrónica; la firma es async no-bloqueante.
async function _secSave(lsKey, json) {
  try {
    localStorage.setItem(lsKey, json);
  } catch (e) {
    if (e.name === 'QuotaExceededError' || e.name === 'NS_ERROR_DOM_QUOTA_REACHED') {
      showToast('Almacenamiento lleno. Elimina fotos o registros antiguos para continuar.', 'error', 8000);
    }
    return;
  }
  try {
    const sig = await _INTEGRITY.sign(json);
    localStorage.setItem(lsKey + '_sig', sig);
  } catch { /* fallo silencioso — dato guardado, firma omitida */ }
}

// Verifica la firma HMAC de cada clave protegida y avisa al usuario si falla.
async function _verifyIntegrity() {
  for (const k of ['aqua_bitacora', 'aqua_afr', 'aqua_mantenimiento']) {
    const json = localStorage.getItem(k);
    const sig  = localStorage.getItem(k + '_sig');
    if (!json || !sig) continue;
    const ok = await _INTEGRITY.verify(json, sig);
    if (!ok) showToast(
      `Alerta: los datos de "${k}" fueron modificados externamente. Verifica la integridad de los registros.`,
      'error', 9000
    );
  }
}

let _logPage = 0;
const LOG_PAGE_SIZE = 25;

// ── ESTADO GLOBAL ────────────────────────────────────────
const APP = {
  currentSection: 'dashboard',
  sidebarCollapsed: false,
  afrStep: 0,
  afrType: 'solido',
  currentParam: 'cloro',
};

// ── NAVEGACIÓN ───────────────────────────────────────────
function sectionInit(section) {
  if (section === 'dashboard')  { renderDashboardIndices(); renderDashboardVencimientos(); renderDashboardGauges(); updateDashReportBtn(); }
  if (section === 'reporte')    { updateReportSummary(); updateReportBtn(); }
  if (section === 'calculadora'){ calcVolume(); calcDosificacion(); }
  if (section === 'lsi')        { _lsiFromBitacora = false; calcLSI(); }
  if (section === 'irapi')      { calcIRAPI(); updateIRAPIBitacoraBtn(); }
  if (section === 'documentos') { renderDocs(); updateVencimientos(); }
  if (section === 'bitacora')      { renderLog(); updateOperadorDatalist(); }
  if (section === 'protocolo')     { renderAFR(); renderAFRIncidents(); }
  if (section === 'mantenimiento') { renderMnt(); checkMntForm(); }
}

function navigate(section, event) {
  if (event) event.preventDefault();

  // Cerrar cualquier modal abierto y restaurar scroll
  ['logDetailOverlay', 'afrDetailOverlay', 'afrEditOverlay', 'mntDetailOverlay'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  });
  document.body.style.overflow = '';

  // Cancelar edición pendiente al cambiar de sección
  if (APP.currentSection === 'mantenimiento' && section !== 'mantenimiento' && editingMntTs) {
    cancelEditMnt();
  }

  const target  = document.getElementById('section-' + section);
  const current = document.querySelector('.page-section.active');
  if (!target || current === target) return;

  // Nav items
  document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
  const navItem = document.querySelector(`[data-section="${section}"]`);
  if (navItem) navItem.classList.add('active');

  APP.currentSection = section;

  if (window.innerWidth <= 900) {
    document.getElementById('sidebar').classList.remove('mobile-open');
    const overlay = document.getElementById('sidebarOverlay');
    if (overlay) overlay.classList.remove('active');
  }

  const swap = () => {
    if (current) current.classList.remove('active', 'leaving');
    target.classList.add('active');
    window.scrollTo(0, 0);
    sectionInit(section);
  };

  if (current) {
    current.classList.add('leaving');
    setTimeout(swap, 180);
  } else {
    swap();
  }
}

function localDateStr(d = new Date()) {
  const offset = d.getTimezoneOffset() * 60000;
  return new Date(d - offset).toISOString().split('T')[0];
}

function _dataAgeMinutes(entry) {
  if (!entry?.fecha) return Infinity;
  const t  = (entry.hora || '00:00').trim();
  const dt = new Date(`${entry.fecha}T${t.length === 5 ? t + ':00' : t}`);
  return isNaN(dt.getTime()) ? Infinity : (Date.now() - dt.getTime()) / 60000;
}

function _fmtAge(minutes) {
  if (!isFinite(minutes)) return '';
  if (minutes <  90)    return `hace ${Math.round(minutes)} min`;
  if (minutes < 1440)   return `hace ${Math.round(minutes / 60)} h`;
  const d = Math.floor(minutes / 1440);
  return `hace ${d} día${d > 1 ? 's' : ''}`;
}

function fmt12h(t, fallback = '–') {
  if (!t) return fallback;
  const [h, m] = t.split(':').map(Number);
  if (isNaN(h) || isNaN(m)) return t;
  const suffix = h < 12 ? 'AM' : 'PM';
  const h12 = h % 12 || 12;
  return `${h12}:${String(m).padStart(2, '0')} ${suffix}`;
}

function clampInput(el, min, max) {
  const v = parseFloat(el.value);
  if (isNaN(v)) return;
  if (v > max) el.value = max;
  else if (v < min) el.value = min;
}

function toggleTooltip(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const wasHidden = el.hidden;
  document.querySelectorAll('.param-tooltip-card').forEach(t => { t.hidden = true; });
  el.hidden = !wasHidden;
  const btn = document.querySelector(`[data-tooltip="${id}"]`);
  if (btn) btn.setAttribute('aria-expanded', String(!wasHidden));
}
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    const overlay = document.getElementById('logDetailOverlay');
    if (overlay && overlay.style.display !== 'none') {
      overlay.style.display = 'none';
      document.body.style.overflow = '';
    }
  }
  if (e.key === 'Enter') {
    const active = document.activeElement;
    if (!active) return;
    if (active.id === 'pinSetupNew' || active.id === 'pinSetupConfirm')      { _pinHandleCreate(); return; }
    if (active.id === 'pinUnlockInput') { if (!_PIN.remainingSecs()) _pinHandleUnlock(); return; }
    if (active.id === 'pinChangeOld' || active.id === 'pinChangeNew' || active.id === 'pinChangeConfirm') { _pinHandleChange(); return; }
  }
});

document.addEventListener('click', e => {
  if (!e.target.closest('.param-help-btn') && !e.target.closest('.param-tooltip-card')) {
    document.querySelectorAll('.param-tooltip-card').forEach(t => { t.hidden = true; });
    document.querySelectorAll('.param-help-btn').forEach(b => b.setAttribute('aria-expanded', 'false'));
  }
});

// ── Event Delegation ─────────────────────────────────────────────
document.addEventListener('click', e => {
  const t = e.target;

  // PIN overlay buttons
  if (t.closest('#btnPinCreate'))       { _pinHandleCreate();       return; }
  if (t.closest('#btnPinUnlock'))       { _pinHandleUnlock();       return; }
  if (t.closest('#btnPinReset'))        { _pinHandleReset();        return; }
  if (t.closest('#btnPinChangeSave'))   { _pinHandleChange();       return; }
  if (t.closest('#btnPinChangeCancel')) { _pinHideOverlay();        return; }
  if (t.closest('#btnLockApp'))         { lockApp();                return; }
  if (t.closest('#btnChangePin'))       { openChangePinView();      return; }
  if (t.closest('#btnRotateData'))      {
    showConfirm(
      '¿Limpiar datos antiguos? Se eliminarán registros de más de 6 meses y las fotos de registros entre 3–6 meses (el texto se conserva).',
      _rotateOldData
    );
    return;
  }

  const navEl = t.closest('[data-navigate]');
  if (navEl) { navigate(navEl.dataset.navigate, e); return; }

  if (t.closest('#sidebarOverlay') || t.closest('#sidebarToggle')) { toggleSidebar(); return; }
  if (t.closest('#themeToggle'))    { toggleTheme();        return; }
  if (t.closest('#shareBtn'))       { compartirEstado();    return; }
  if (t.closest('#btnDashReport'))  { dashboardReportClick(); return; }

  const trendParamEl = t.closest('.trend-btn[data-param]');
  if (trendParamEl) { setTrendParam(trendParamEl.dataset.param); return; }

  const trendDayEl = t.closest('.trend-day[data-days]');
  if (trendDayEl) { setTrendDays(Number(trendDayEl.dataset.days)); return; }

  if (t.closest('.calc-to-bitacora'))    { navigateCalcToBitacora(e); return; }
  if (t.closest('#btnCalcLSIBitacora'))  { calcLSIFromBitacora();     return; }
  if (t.closest('#btnCalcIRAPIBitacora')) { calcIRAPIFromBitacora();  return; }

  const tooltipBtn = t.closest('[data-tooltip]');
  if (tooltipBtn) { toggleTooltip(tooltipBtn.dataset.tooltip); return; }

  const photoCapture = t.closest('.btn-photo-capture[data-photo]');
  if (photoCapture) { triggerPhoto(photoCapture.dataset.photo); return; }

  const photoRemove = t.closest('.photo-remove[data-photo]');
  if (photoRemove) { removePhoto(photoRemove.dataset.photo); return; }

  if (t.closest('#btnSaveLog'))    { saveLog();        return; }
  if (t.closest('#btnSaveMnt'))       { saveMnt();          return; }
  if (t.closest('#btnCancelEdit'))    { cancelEditLog();    return; }
  if (t.closest('#btnCancelEditMnt')) { cancelEditMnt();    return; }
  if (t.closest('#btnClearFilter')) { clearLogFilter(); return; }

  const afrTypeBtn = t.closest('[data-afr-type]');
  if (afrTypeBtn) { setAFRType(afrTypeBtn.dataset.afrType); return; }

  if (t.closest('#afrPrev')) { afrStep(-1); return; }
  if (t.closest('#afrNext')) {
    const steps = AFR_STEPS[APP.afrType];
    if (APP.afrStep === steps.length - 1) finishAFR();
    else afrStep(1);
    return;
  }
  if (t.closest('#btnResetAFR')) { resetAFR(); return; }

  if (t.closest('#btnClearRepRange')) { clearRepRange();  return; }
  if (t.closest('#btnGeneratePDF'))   { generatePDF();    return; }

  const profileBtn = t.closest('[data-profile]');
  if (profileBtn) { setDocsProfile(profileBtn.dataset.profile); return; }

  const conceptoBtn = t.closest('.concepto-opt[data-val]');
  if (conceptoBtn) { selectConcepto(conceptoBtn.dataset.val); return; }

  if (t.id === 'afrEditOverlay')         { closeAFREdit(e);          return; }
  if (t.closest('#btnAfrEditCancel'))    { closeAFREdit();            return; }
  if (t.closest('#btnAfrEditSave'))      { saveAFREdit();             return; }

  if (t.id === 'confirmOverlay')         { closeConfirmOverlay(e);   return; }
  if (t.closest('#confirmCancelBtn'))    { closeConfirmOverlay();     return; }
  if (t.closest('#confirmOkBtn'))        {
    const cb = _confirmOkCb;
    closeConfirmOverlay();
    if (cb) cb();
    return;
  }

  if (t.id === 'afrDetailOverlay')       { closeAFRDetail(e);        return; }
  if (t.closest('#afrDetailOverlay .log-detail-close')) { closeAFRDetail(); return; }

  if (t.id === 'logDetailOverlay')       { closeLogDetail(e);        return; }
  if (t.closest('#logDetailOverlay .log-detail-close')) { closeLogDetail(); return; }

  if (t.id === 'mntDetailOverlay')       { closeMntDetail(e);        return; }
  if (t.closest('#mntDetailOverlay .log-detail-close')) { closeMntDetail(); return; }

  if (t.closest('#preloaderBtn')) { preloaderNext(); return; }
  const dismissBtn = t.closest('[data-dismiss]');
  if (dismissBtn) { dismissPreloader(dismissBtn.dataset.dismiss); return; }

  // Bitácora — tabla (filas clickeables + botones de acción)
  const logRow = t.closest('.log-row-clickable[data-ts]');
  if (logRow) {
    const ts = Number(logRow.dataset.ts);
    if (t.closest('.btn-edit-log'))   { editLog(ts);  return; }
    if (t.closest('.btn-delete-log')) { deleteLog(ts); return; }
    if (t.closest('.btn-cam-log'))    { viewLog(ts);  return; }
    if (!t.closest('.log-row-actions')) { viewLog(ts); return; }
    return;
  }

  // Bitácora — paginación
  const pgBtn = t.closest('.log-pg-btn[data-page]');
  if (pgBtn && !pgBtn.disabled) { goLogPage(Number(pgBtn.dataset.page)); return; }

  // Mantenimiento — lista
  const mntItem = t.closest('.mnt-item[data-ts]');
  if (mntItem) {
    const ts = Number(mntItem.dataset.ts);
    if (t.closest('.btn-edit-log'))      { editMnt(ts);       return; }
    if (t.closest('.btn-delete-log'))    { deleteMnt(ts);     return; }
    if (!t.closest('.mnt-item-actions')) { openMntDetail(ts); return; }
    return;
  }

  // AFR — lista (ítems clickeables + botones de acción)
  const afrItem = t.closest('.afr-incident-item[data-ts]');
  if (afrItem) {
    const ts = Number(afrItem.dataset.ts);
    if (t.closest('.btn-edit-log'))   { editAFRIncident(ts);   return; }
    if (t.closest('.btn-delete-log')) { deleteAFRIncident(ts); return; }
    if (!t.closest('.afr-incident-actions')) { viewAFRIncident(ts); return; }
    return;
  }

  // Documentos — ítems del checklist
  const docsItem = t.closest('.docs-item[data-doc-id]');
  if (docsItem) { toggleDocItem(docsItem.dataset.docId); return; }

  // Documentos — ir a vencimientos
  if (t.closest('.js-go-venc')) { goToVencimientos(e); return; }
});

document.addEventListener('blur', e => {
  const el = e.target;
  if (el.type === 'number' && el.min !== '' && el.max !== '') {
    clampInput(el, parseFloat(el.min), parseFloat(el.max));
  }
}, true);

document.addEventListener('input', e => {
  const el = e.target;
  const id = el.id;

  if (id === 'poolLength' || id === 'poolWidth' || id === 'poolDiam' || id === 'poolDepth') {
    calcVolume(); return;
  }

  if (['calcCloroActual','calcCloroObj','calcPhActual','calcPhObj',
       'calcAlcActual','calcAlcObj','calcCyaActual','calcCyaObj','calcCloroCombActual'].includes(id)) {
    calcDosificacion(); return;
  }

  if (id === 'lsiPh' || id === 'lsiTemp' || id === 'lsiHard' || id === 'lsiAlk') {
    _lsiFromBitacora = false; calcLSI(); return;
  }

  if (id === 'microLabValue')  { applyMicroLab(); return; }
  if (id === 'sliderMicro')    { calcIRAPI(); hideMicroReminder(); return; }
  if (id === 'sliderCloro' || id === 'sliderAlk' || id === 'sliderOtros') { calcIRAPI(); return; }

  if (['logDate','logTime','logCloro','logPh','logAlc','logCya',
       'logCloroComb','logTurb','logTemp','logDureza','logOrp','logTds','logCond'].includes(id)) {
    checkLogForm(); return;
  }

  if (['mntFecha','mntTecnico','mntDescripcion'].includes(id)) { checkMntForm(); return; }

  if (id === 'repNombre' || id === 'repResponsable' || id === 'repUbicacion' || id === 'repVolumen') {
    saveReportFields(); return;
  }

  if (id === 'fechaSalvavidas') { updateVencimientos(); return; }

  if (id === 'filterDesde' || id === 'filterHasta' || id === 'filterOperador') { renderLog(); return; }
});

document.addEventListener('change', e => {
  const id = e.target.id;
  if (id === 'poolShape')        { updateShapeFields();  return; }
  if (id === 'filterFueraRango') { renderLog();           return; }
  if (id === 'repDesde' || id === 'repHasta') { onRepRangeChange(); return; }
  if (id === 'mntArea') { checkMntForm(); return; }
});

function navigateCalcToBitacora(event) {
  const cloro    = document.getElementById('calcCloroActual')?.value;
  const ph       = document.getElementById('calcPhActual')?.value;
  const alc      = document.getElementById('calcAlcActual')?.value;
  const cya      = document.getElementById('calcCyaActual')?.value;
  const clorocomb= document.getElementById('calcCloroCombActual')?.value;
  navigate('bitacora', event);
  setTimeout(() => {
    if (cloro)    { const el = document.getElementById('logCloro');    if (el && !el.value) el.value = cloro; }
    if (ph)       { const el = document.getElementById('logPh');       if (el && !el.value) el.value = ph; }
    if (alc)      { const el = document.getElementById('logAlc');      if (el && !el.value) el.value = alc; }
    if (cya)      { const el = document.getElementById('logCya');      if (el && !el.value) el.value = cya; }
    if (clorocomb){ const el = document.getElementById('logCloroComb');if (el && !el.value) el.value = clorocomb; }
    checkLogForm();
  }, 220);
}

// ── TOAST ────────────────────────────────────────────────
function showToast(msg, type = 'info', duration = 3500) {
  const icons = { success: '✓', warning: '⚠', error: '✕', info: 'ℹ' };
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;

  const iconEl = document.createElement('span');
  iconEl.className = 'toast-icon';
  iconEl.textContent = icons[type] || icons.info;

  const msgEl = document.createElement('span');
  msgEl.className = 'toast-msg';
  msgEl.textContent = msg;

  const closeBtn = document.createElement('button');
  closeBtn.className = 'toast-close';
  closeBtn.textContent = '✕';
  closeBtn.addEventListener('click', () => closeBtn.closest('.toast').remove());

  toast.append(iconEl, msgEl, closeBtn);
  container.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('toast-visible'));
  setTimeout(() => {
    toast.classList.remove('toast-visible');
    setTimeout(() => toast.remove(), 280);
  }, duration);
}

// ── CONFIRM MODAL ─────────────────────────────────────────
let _confirmOkCb = null;
let _afrEditTs   = null;

function showConfirm(msg, onOk) {
  _confirmOkCb = onOk;
  document.getElementById('confirmBody').textContent = msg;
  document.getElementById('confirmOverlay').style.display = 'flex';
}

function closeConfirmOverlay(e) {
  if (e && e.target !== document.getElementById('confirmOverlay')) return;
  document.getElementById('confirmOverlay').style.display = 'none';
  _confirmOkCb = null;
}

// ── THEME TOGGLE ─────────────────────────────────────────
function toggleTheme() {
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  setTheme(isDark ? 'light' : 'dark');
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('aqua_theme', theme);
  const btn = document.getElementById('themeToggle');
  if (btn) btn.setAttribute('aria-label', theme === 'dark' ? 'Cambiar a modo claro' : 'Cambiar a modo oscuro');
}

(function initTheme() {
  const saved = localStorage.getItem('aqua_theme');
  if (saved) { setTheme(saved); return; }
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  setTheme(prefersDark ? 'dark' : 'light');
}());

// ── SIDEBAR TOGGLE ───────────────────────────────────────
function toggleSidebar() {
  const layout   = document.getElementById('appLayout');
  const sidebar  = document.getElementById('sidebar');
  const overlay  = document.getElementById('sidebarOverlay');

  if (window.innerWidth <= 900) {
    const isOpen = sidebar.classList.toggle('mobile-open');
    overlay.classList.toggle('active', isOpen);
  } else {
    APP.sidebarCollapsed = !APP.sidebarCollapsed;
    sidebar.classList.toggle('collapsed', APP.sidebarCollapsed);
    layout.classList.toggle('sidebar-collapsed', APP.sidebarCollapsed);
  }
}

// ── CANVAS GAUGE (semicírculo) ───────────────────────────
function drawGauge(canvasId, value, min, max, color) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const cx = W / 2, cy = H - 8;
  const r  = Math.min(W, H * 2) * 0.42;

  // Track
  ctx.beginPath();
  ctx.arc(cx, cy, r, Math.PI, 0);
  ctx.strokeStyle = '#e2e8f0';
  ctx.lineWidth   = 10;
  ctx.lineCap     = 'round';
  ctx.stroke();

  // Fill
  const pct   = Math.max(0, Math.min(1, (value - min) / (max - min)));
  const start = Math.PI;
  const end   = Math.PI + pct * Math.PI;

  ctx.beginPath();
  ctx.arc(cx, cy, r, start, end);
  ctx.strokeStyle = color || '#0cb86a';
  ctx.lineWidth   = 10;
  ctx.lineCap     = 'round';
  ctx.stroke();

  // Needle
  const angle = Math.PI + pct * Math.PI;
  const nx = cx + (r - 4) * Math.cos(angle);
  const ny = cy + (r - 4) * Math.sin(angle);

  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.lineTo(nx, ny);
  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth   = 2;
  ctx.stroke();

  // Pivot
  ctx.beginPath();
  ctx.arc(cx, cy, 5, 0, Math.PI * 2);
  ctx.fillStyle = '#1e293b';
  ctx.fill();
}

// ── GAUGE LSI (rojo-verde-amarillo) ─────────────────────
function drawLSIGauge(canvasId, lsiValue) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const cx = W / 2, cy = H - 10;
  const r  = Math.min(W, H * 2) * 0.40;

  // Zonas Res. 234/2026: -0.3 a +0.5 (asimétrico)
  // lsi=-0.3 → pct=0.35 → 1.35π | lsi=+0.5 → pct=0.75 → 1.75π
  const segments = [
    { start: Math.PI,        end: Math.PI * 1.35, color: '#ef4444' },
    { start: Math.PI * 1.35, end: Math.PI * 1.75, color: '#0cb86a' },
    { start: Math.PI * 1.75, end: Math.PI * 2,    color: '#f59e0b' },
  ];

  segments.forEach(seg => {
    ctx.beginPath();
    ctx.arc(cx, cy, r, seg.start, seg.end);
    ctx.strokeStyle = seg.color;
    ctx.lineWidth   = 14;
    ctx.lineCap     = 'butt';
    ctx.stroke();
  });

  // Needle: LSI va de -1 a +1, mapeado a 0-180°
  const pct   = Math.max(0, Math.min(1, (lsiValue + 1) / 2));
  const angle = Math.PI + pct * Math.PI;
  const nx = cx + (r - 6) * Math.cos(angle);
  const ny = cy + (r - 6) * Math.sin(angle);

  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.lineTo(nx, ny);
  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth   = 2.5;
  ctx.stroke();

  ctx.beginPath();
  ctx.arc(cx, cy, 6, 0, Math.PI * 2);
  ctx.fillStyle = '#1e293b';
  ctx.fill();

  // Labels
  ctx.fillStyle = '#ef4444';
  ctx.font = '11px Inter';
  ctx.fillText('Corrosiva', 4, cy - r + 20);

  ctx.fillStyle = '#f59e0b';
  ctx.font = '11px Inter';
  ctx.fillText('Incrustante', W - 80, cy - r + 20);
}

// ── DASHBOARD: GAUGES ────────────────────────────────────
const PARAM_DEFS = [
  { id: 'g-cloro',     key: 'cloro',     label: 'Cloro libre residual',    unit: 'ppm',   min: 0,  max: 6,    range: 'Rango: 2–4 ppm',    normMin: 2.0,  normMax: 4.0,
    icon: '<path d="M12 2s-7 9-7 13a7 7 0 0 0 14 0c0-4-7-13-7-13z"/>' },
  { id: 'g-clorocomb', key: 'clorocomb', label: 'Cloro combinado',         unit: 'ppm',   min: 0,  max: 1,    range: 'Máx. 0.3 ppm',      normMin: 0,    normMax: 0.3,
    icon: '<path d="M9 3h6m-3 0v7l-4.5 7.38A2 2 0 0 0 9.26 20h5.48a2 2 0 0 0 1.74-2.97L12 10V3"/>' },
  { id: 'g-ph',        key: 'ph',        label: 'pH',                      unit: '',      min: 6,  max: 9,    range: 'Rango: 6.8–7.3',    normMin: 6.8,  normMax: 7.3,
    icon: '<line x1="8.5" y1="2" x2="15.5" y2="2"/><path d="M14.5 2v17.5c0 1.38-1.12 2.5-2.5 2.5s-2.5-1.12-2.5-2.5V2"/>' },
  { id: 'g-alc',       key: 'alc',       label: 'Alcalinidad total',       unit: 'ppm',   min: 0,  max: 200,  range: 'Rango: 20–150 ppm',   normMin: 20,   normMax: 150,
    icon: '<path d="M2 12c1.5-2 3-2 4.5 0s3 2 4.5 0 3-2 4.5 0 3 2 4.5 0"/><path d="M2 17c1.5-2 3-2 4.5 0s3 2 4.5 0 3-2 4.5 0 3 2 4.5 0"/>' },
  { id: 'g-dureza',    key: 'dureza',    label: 'Dureza cálcica',          unit: 'ppm',   min: 0,  max: 800,  range: 'Rango: 200–700 ppm',  normMin: 200,  normMax: 700,
    icon: '<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>' },
  { id: 'g-cya',       key: 'cya',       label: 'Estabilizador (CYA)',     unit: 'ppm',   min: 0,  max: 100,  range: 'Rango: 0–75 ppm',     normMin: 0,    normMax: 75,
    icon: '<circle cx="12" cy="12" r="4"/><line x1="12" y1="2" x2="12" y2="4"/><line x1="12" y1="20" x2="12" y2="22"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="2" y1="12" x2="4" y2="12"/><line x1="20" y1="12" x2="22" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>' },
  { id: 'g-turb',      key: 'turb',      label: 'Transparencia',           unit: 'UNT',   min: 0,  max: 1,    range: 'Rango: 0–0.5 UNT', normMin: 0,    normMax: 0.5,
    icon: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>' },
  { id: 'g-temp',      key: 'temp',      label: 'Temperatura',             unit: '°C',    min: 15, max: 45,   range: 'Máx. 40 °C',        normMin: 0,    normMax: 40,
    icon: '<path d="M14 14.76V3.5a2.5 2.5 0 0 0-5 0v11.26a4.5 4.5 0 1 0 5 0z"/>' },
  { id: 'g-orp',       key: 'orp',       label: 'Oxidación (ORP)',         unit: 'mV',    min: 0,  max: 900,  range: 'Óptimo: 650–700 mV', normMin: 0,    normMax: 700,  warnBelow: 650,
    icon: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>' },
  { id: 'g-tds',       key: 'tds',       label: 'Sólidos disueltos (TDS)', unit: 'mg/L',  min: 0,  max: 3000, range: '1000–1200 mg/L',    normMin: 1000, normMax: 1200,
    icon: '<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>' },
  { id: 'g-cond',      key: 'cond',      label: 'Conductividad eléctrica', unit: 'µS/cm', min: 0,  max: 5000, range: '2000–2400 µS/cm',   normMin: 2000, normMax: 2400,
    icon: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>' },
];

function setTrendParam(param) {
  _trendParam = param;
  document.querySelectorAll('.trend-btn[data-param]').forEach(b =>
    b.classList.toggle('active', b.dataset.param === param));
  renderTrendChart();
}

function setTrendDays(days) {
  _trendDays = days;
  document.querySelectorAll('.trend-day[data-days]').forEach(b =>
    b.classList.toggle('active', +b.dataset.days === days));
  renderTrendChart();
}

function renderTrendChart() {
  const card   = document.getElementById('trendCard');
  const canvas = document.getElementById('trendCanvas');
  if (!card || !canvas) return;

  const log = getLog();
  if (!log.length) { card.style.display = 'none'; return; }
  card.style.display = 'block';

  const paramDef = PARAM_DEFS.find(p => p.key === _trendParam);
  if (!paramDef) return;

  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - _trendDays);
  const cutoffStr = cutoff.toISOString().slice(0, 10);

  const data = log
    .filter(e => e.fecha >= cutoffStr && e[_trendParam] != null && !isNaN(e[_trendParam]))
    .sort((a, b) => a.fecha.localeCompare(b.fecha) || (a.hora || '').localeCompare(b.hora || ''));

  const wrap = canvas.parentElement;
  const W    = wrap.clientWidth || 600;
  const H    = 200;
  const dpr  = window.devicePixelRatio || 1;
  canvas.width  = W * dpr;
  canvas.height = H * dpr;
  canvas.style.width  = '100%';
  canvas.style.height = H + 'px';

  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);

  const PAD = { top: 16, right: 20, bottom: 38, left: 46 };
  const cW  = W - PAD.left - PAD.right;
  const cH  = H - PAD.top  - PAD.bottom;

  const toY = v => PAD.top  + cH - Math.max(0, Math.min(1, (v - paramDef.min) / (paramDef.max - paramDef.min))) * cH;
  const toX = i => data.length < 2 ? PAD.left + cW / 2 : PAD.left + (i / (data.length - 1)) * cW;

  const isDark    = document.documentElement.getAttribute('data-theme') === 'dark';
  const gridClr   = isDark ? 'rgba(255,255,255,.07)' : 'rgba(0,0,0,.07)';
  const textClr   = isDark ? '#94a3b8' : '#64748b';
  const dotBorder = isDark ? '#1e293b' : '#ffffff';

  // Grid + Y labels
  for (let i = 0; i <= 4; i++) {
    const y   = PAD.top + (i / 4) * cH;
    const val = paramDef.max - (i / 4) * (paramDef.max - paramDef.min);
    ctx.strokeStyle = gridClr; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(PAD.left, y); ctx.lineTo(PAD.left + cW, y); ctx.stroke();
    ctx.fillStyle = textClr;
    ctx.font = '10px system-ui,sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(parseFloat(val.toFixed(1)), PAD.left - 6, y + 3.5);
  }

  // Normative range band
  const bandTop = toY(paramDef.normMax);
  const bandBot = toY(paramDef.normMin);
  ctx.fillStyle = 'rgba(16,185,129,.09)';
  ctx.fillRect(PAD.left, bandTop, cW, bandBot - bandTop);
  ctx.strokeStyle = 'rgba(16,185,129,.3)'; ctx.lineWidth = 1;
  ctx.setLineDash([4, 3]);
  ctx.beginPath(); ctx.moveTo(PAD.left, bandTop); ctx.lineTo(PAD.left + cW, bandTop); ctx.stroke();
  ctx.beginPath(); ctx.moveTo(PAD.left, bandBot);  ctx.lineTo(PAD.left + cW, bandBot);  ctx.stroke();
  ctx.setLineDash([]);

  if (!data.length) {
    ctx.fillStyle = textClr;
    ctx.font = '13px system-ui,sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Sin registros en este período', PAD.left + cW / 2, PAD.top + cH / 2 + 5);
    return;
  }

  // Line
  ctx.beginPath();
  data.forEach((e, i) => {
    const x = toX(i), y = toY(e[_trendParam]);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = '#0ea5e9'; ctx.lineWidth = 2;
  ctx.lineJoin = 'round'; ctx.lineCap = 'round';
  ctx.stroke();

  // Dots + X labels
  const labelStep = Math.ceil(data.length / 10);
  data.forEach((e, i) => {
    const x = toX(i), y = toY(e[_trendParam]);
    const inRange = e[_trendParam] >= paramDef.normMin && e[_trendParam] <= paramDef.normMax;
    const isWarn  = inRange && paramDef.warnBelow !== undefined && e[_trendParam] < paramDef.warnBelow;
    ctx.beginPath();
    ctx.arc(x, y, 3.5, 0, Math.PI * 2);
    ctx.fillStyle = !inRange ? '#ef4444' : isWarn ? '#f59e0b' : '#0cb86a';
    ctx.strokeStyle = dotBorder; ctx.lineWidth = 1.5;
    ctx.fill(); ctx.stroke();
    if (data.length <= 10 || i % labelStep === 0 || i === data.length - 1) {
      const [, m, d] = e.fecha.split('-');
      ctx.fillStyle = textClr;
      ctx.font = '10px system-ui,sans-serif';
      ctx.textAlign = 'center'; ctx.lineWidth = 1;
      ctx.fillText(`${d}/${m}`, x, H - PAD.bottom + 15);
    }
  });

  // Y unit
  if (paramDef.unit) {
    ctx.save();
    ctx.translate(11, PAD.top + cH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillStyle = textClr;
    ctx.font = '10px system-ui,sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(paramDef.unit, 0, 0);
    ctx.restore();
  }
}

function renderDashboardIndices() {
  const el = document.getElementById('dashIndices');
  if (!el) return;

  if (!getLog().length) { el.innerHTML = ''; return; }

  const irapiResult = JSON.parse(sessionStorage.getItem('aqua_irapi_result') || 'null');
  const lastWithISL = getLog().find(e => e.isl != null);
  const lsiResult   = lastWithISL ? { lsi: lastWithISL.isl, status: lastWithISL.islStatus } : null;

  if (!irapiResult && !lsiResult) { el.innerHTML = ''; return; }

  const irapiColor = !irapiResult ? '#94a3b8'
    : irapiResult.score <= 10 ? '#0cb86a'
    : irapiResult.score <= 35 ? '#f59e0b'
    : irapiResult.score <= 75 ? '#ea580c'
    : '#ef4444';

  const lsiColor = !lsiResult ? '#94a3b8'
    : lsiResult.status === 'Equilibrada' ? '#0cb86a'
    : lsiResult.status === 'Incrustante' ? '#f59e0b'
    : '#ef4444';

  const irapiCard = irapiResult ? `
    <div class="dash-index-card">
      <div class="dash-index-top">
        <span class="dash-index-name">Riesgo sanitario (IRAPI)</span>
        <span class="dash-index-badge" style="background:${irapiColor}20;color:${irapiColor}">${irapiResult.label}</span>
      </div>
      <div class="dash-index-score" style="color:${irapiColor}">${irapiResult.score}</div>
      <div class="dash-index-bar-bg">
        <div class="dash-index-bar-fill" style="width:${Math.min(irapiResult.score,100)}%;background:${irapiColor}"></div>
      </div>
      <div class="dash-index-hint">Escala 0–100</div>
    </div>` : '';

  const lsiCard = lsiResult ? `
    <div class="dash-index-card">
      <div class="dash-index-top">
        <span class="dash-index-name">Equilibrio del agua (ISL)</span>
        <span class="dash-index-badge" style="background:${lsiColor}20;color:${lsiColor}">${lsiResult.status}</span>
      </div>
      <div class="dash-index-score" style="color:${lsiColor}">${lsiResult.lsi.toFixed(2)}</div>
      <div class="dash-index-bar-bg">
        <div class="dash-index-bar-fill" style="width:${Math.min(Math.abs(lsiResult.lsi)/2*100,100)}%;background:${lsiColor}"></div>
      </div>
      <div class="dash-index-hint">Rango: −0.3 a +0.5</div>
    </div>` : '';

  el.innerHTML = `<div class="dash-indices-grid">${irapiCard}${lsiCard}</div>`;
}

function goToVencimientos(event) {
  navigate('documentos', event);
  setTimeout(() => {
    const card = document.getElementById('cardVencimientos');
    if (card) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
    card?.classList.add('venc-highlight');
    setTimeout(() => card?.classList.remove('venc-highlight'), 1800);
  }, 320);
}

function renderDashboardVencimientos() {
  const el = document.getElementById('dashVencAlerts');
  if (!el) return;

  const profile = getDocsProfile();
  if (profile !== 'publico') { el.style.display = 'none'; return; }

  const dates = JSON.parse(localStorage.getItem('aqua_docs_dates') || '{}');

  const alerts = [];

  const val = dates['fechaSalvavidas'];
  if (val) {
    const days = Math.ceil((new Date(val + 'T00:00:00') - new Date()) / 86400000);
    if (days <= 30) {
      const cls = days < 0 || days <= 10 ? 'venc-danger' : 'venc-warning';
      const msg = days < 0 ? 'VENCIDO' : `Vence en ${days} día${days === 1 ? '' : 's'}`;
      alerts.push({ label: 'Certificación del salvavidas', msg, cls });
    }
  }

  const concepto = dates['concepto'];
  if (concepto === 'rojo')    alerts.push({ label: 'Concepto sanitario', msg: 'Desfavorable',          cls: 'venc-danger'  });
  else if (concepto === 'amarillo') alerts.push({ label: 'Concepto sanitario', msg: 'Con Requerimientos', cls: 'venc-warning' });

  if (!alerts.length) { el.style.display = 'none'; return; }

  el.style.display = 'block';
  el.innerHTML = `
    <div class="dash-venc-wrap">
      <div class="dash-venc-header">
        <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <strong>Documentos con vencimiento próximo</strong>
        <button class="btn btn-sm btn-outline js-go-venc" style="margin-left:auto;font-size:0.78rem;padding:4px 10px">Ver vencimientos</button>
      </div>
      ${alerts.map(({ label, msg, cls }) =>
        `<div class="dash-venc-item ${cls}"><span>${label}</span><span class="venc-badge">${msg}</span></div>`
      ).join('')}
    </div>
  `;
}

function renderDashboardGauges() {
  const grid = document.getElementById('gaugesGrid');
  if (!grid) return;

  const log  = getLog();
  const last = log[0];
  const prev = log[1] || null;

  // Panel de guía de inicio
  const emptyGuide = document.getElementById('dashEmptyGuide');
  if (emptyGuide) emptyGuide.style.display = !last ? 'block' : 'none';

  // Sin mediciones aún
  const shareBtn = document.getElementById('shareBtn');
  if (!last) {
    grid.innerHTML = '';
    if (shareBtn) shareBtn.style.display = 'none';
    const hero  = document.getElementById('complianceHero');
    const title = document.getElementById('complianceTitle');
    const badge = document.getElementById('complianceBadge');
    hero.classList.remove('non-compliant');
    title.textContent = 'Sin datos de medición';
    badge.className   = 'badge badge-warning';
    badge.textContent = '– Sin datos';
    const pt = document.getElementById('paramsTitle');
    if (pt) pt.textContent = 'Parámetros del agua · sin mediciones';
    return;
  }
  if (shareBtn) shareBtn.style.display = 'flex';

  // Antigüedad del dato
  const ageMin   = _dataAgeMinutes(last);
  const ageWarn  = ageMin > 8  * 60;  // > 8 h
  const ageStale = ageMin > 24 * 60;  // > 24 h

  // Subtítulo con edad relativa
  const pt = document.getElementById('paramsTitle');
  if (pt) {
    const quien   = last.operador ? ` · ${last.operador}` : '';
    const ageText = isFinite(ageMin) ? ` · ${_fmtAge(ageMin)}` : '';
    pt.textContent = `Parámetros del agua · ${last.fecha || ''} ${fmt12h(last.hora, '')}${quien}${ageText}`;
  }

  grid.innerHTML = '';
  let allCumple = true;

  PARAM_DEFS.forEach(p => {
    const value     = last[p.key] ?? null;
    const prevValue = prev ? (prev[p.key] ?? null) : null;
    const cumple    = value !== null && value >= p.normMin && value <= p.normMax;
    const warn      = cumple && p.warnBelow !== undefined && value < p.warnBelow;
    if (value !== null && !cumple) allCumple = false;
    const color   = value === null ? '#94a3b8' : !cumple ? '#ef4444' : warn ? '#f59e0b' : '#0cb86a';
    const display = value !== null ? value : '–';

    let trendHtml = '';
    if (value !== null && prevValue !== null) {
      const diff = value - prevValue;
      const abs  = parseFloat(Math.abs(diff).toFixed(2));
      if (abs < 0.005) {
        trendHtml = '<div class="gauge-trend trend-stable">&#8594; Sin cambio</div>';
      } else if (diff > 0) {
        trendHtml = `<div class="gauge-trend trend-up">&#8593; +${abs}</div>`;
      } else {
        trendHtml = `<div class="gauge-trend trend-down">&#8595; &minus;${abs}</div>`;
      }
    }

    const card = document.createElement('div');
    card.className = 'gauge-card';
    card.innerHTML = `
      <div class="gauge-canvas-wrap">
        <canvas id="${p.id}" width="140" height="80"></canvas>
      </div>
      <div class="gauge-val" style="color:${color}">
        ${display}<span class="unit">${p.unit}</span>
      </div>
      <div class="gauge-name">
        <svg class="gauge-param-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${p.icon}</svg>
        ${p.label}
      </div>
      <div class="gauge-range">${p.range}</div>
      <div class="gauge-badge">
        <span class="badge ${value === null ? 'badge-warning' : !cumple ? 'badge-danger' : warn ? 'badge-warning' : 'badge-success'}">
          ${value === null ? '– Sin dato' : !cumple ? '&#10007; No cumple' : warn ? '&#9888; Eficacia baja' : '&#10003; Cumple'}
        </span>
      </div>
      ${trendHtml}
    `;
    grid.appendChild(card);
  });

  setTimeout(() => {
    PARAM_DEFS.forEach(p => {
      const value  = last[p.key] ?? null;
      if (value === null) { drawGauge(p.id, p.min, p.min, p.max, '#cbd5e1'); return; }
      const cumple = value >= p.normMin && value <= p.normMax;
      const warn   = cumple && p.warnBelow !== undefined && value < p.warnBelow;
      drawGauge(p.id, value, p.min, p.max, !cumple ? '#ef4444' : warn ? '#f59e0b' : '#0cb86a');
    });
    renderTrendChart();
  }, 50);

  // Hero
  const hero       = document.getElementById('complianceHero');
  const title      = document.getElementById('complianceTitle');
  const badge      = document.getElementById('complianceBadge');
  const ageBanner  = document.getElementById('dataAgeWarning');
  const clockSVG   = `<svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`;

  hero.classList.remove('non-compliant', 'stale');

  if (ageStale) {
    // > 24 h — estado desconocido, no podemos afirmar que sigue apta
    hero.classList.add('stale');
    title.textContent = 'Estado desconocido';
    badge.className   = 'badge badge-warning';
    badge.textContent = '⚠ Sin verificar hoy';
    if (ageBanner) {
      ageBanner.style.display = 'flex';
      ageBanner.className = 'data-age-banner age-stale';
      ageBanner.innerHTML = `${clockSVG}
        <span>Última medición <strong>${_fmtAge(ageMin)}</strong> — el agua puede haber cambiado.
        Registrar nueva medición para conocer el estado actual.</span>`;
    }
  } else if (ageWarn) {
    // 8–24 h — datos envejecidos pero usamos el resultado real
    if (allCumple) {
      title.textContent = 'Apta para uso público';
      badge.className   = 'badge badge-success';
      badge.textContent = '✓ Cumple';
    } else {
      hero.classList.add('non-compliant');
      title.textContent = 'Fuera de parámetros';
      badge.className   = 'badge badge-danger';
      badge.textContent = '✗ No cumple';
    }
    if (ageBanner) {
      ageBanner.style.display = 'flex';
      ageBanner.className = 'data-age-banner age-warn';
      ageBanner.innerHTML = `${clockSVG}
        <span>Datos de <strong>${_fmtAge(ageMin)}</strong> — se recomienda registrar una nueva medición hoy.</span>`;
    }
  } else {
    // < 8 h — datos frescos, mostrar normalmente
    if (allCumple) {
      title.textContent = 'Apta para uso público';
      badge.className   = 'badge badge-success';
      badge.textContent = '✓ Cumple';
    } else {
      hero.classList.add('non-compliant');
      title.textContent = 'Fuera de parámetros';
      badge.className   = 'badge badge-danger';
      badge.textContent = '✗ No cumple';
    }
    if (ageBanner) ageBanner.style.display = 'none';
  }
}

// ── COMPARTIR ESTADO ──────────────────────────────────────
function compartirEstado() {
  const log = getLog();
  if (!log.length) {
    showToast('Sin datos para compartir. Registra una medición primero.', 'warning');
    return;
  }
  const last = log[0];

  const hero          = document.getElementById('complianceHero');
  const titleEl       = document.getElementById('complianceTitle');
  const isNonCompliant = hero ? hero.classList.contains('non-compliant') : false;
  const isStale        = hero ? hero.classList.contains('stale')         : false;
  const stateEmoji     = isStale ? '⚠️' : (isNonCompliant ? '❌' : '✅');
  const stateLabel     = titleEl ? titleEl.textContent.trim() : '–';
  const normLabel      = isStale
    ? 'Estado no verificado — requiere nueva medición'
    : (isNonCompliant ? 'No cumple Resolución 234/2026' : 'Cumple Resolución 234/2026');

  const fecha = last.fecha || '–';
  const hora  = last.hora  ? ` · ${fmt12h(last.hora)}`    : '';
  const op    = last.operador ? `\nOperador: ${last.operador}` : '';

  const paramLines = PARAM_DEFS
    .map(p => {
      const val = last[p.key];
      if (val == null || val === '') return null;
      const cumple = +val >= p.normMin && +val <= p.normMax;
      return `${cumple ? '✓' : '✗'} ${p.label}: ${val} ${p.unit}`.trimEnd();
    })
    .filter(Boolean);

  // Leer score IRAPI del dashboard si está disponible
  const irapiBarEl  = document.getElementById('irapiBarFill');
  const irapiLblEl  = document.getElementById('irapiScoreLabel');
  const irapiScore  = irapiBarEl  ? Math.round(parseFloat(irapiBarEl.style.width))  : null;
  const irapiLabel  = irapiLblEl  ? irapiLblEl.textContent.trim() : null;
  const irapiLine   = (irapiScore != null && !isNaN(irapiScore) && irapiLabel)
    ? `\nIRAPI: ${irapiScore} — ${irapiLabel}` : '';

  const text = [
    '🏊 Brazada Aqua Tech — Estado de piscina',
    `📅 ${fecha}${hora}${op}`,
    '',
    `${stateEmoji} ${stateLabel}`,
    normLabel,
    '',
    'Parámetros:',
    ...paramLines,
    irapiLine,
    '',
    '— Generado con Brazada Aqua Tech',
  ].join('\n');

  const tryClipboard = () => {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text)
        .then(()  => showToast('Resumen copiado al portapapeles', 'success'))
        .catch(() => showToast('No se pudo copiar. Permite el acceso al portapapeles o copia manualmente.', 'error'));
    } else {
      showToast('Portapapeles no disponible en este navegador.', 'error');
    }
  };

  if (navigator.share) {
    navigator.share({ title: 'Estado de piscina — Brazada Aqua Tech', text })
      .catch(err => { if (err.name !== 'AbortError') tryClipboard(); });
  } else {
    tryClipboard();
  }
}


// ── CALCULADORA: VOLUMEN ─────────────────────────────────
function updateShapeFields() {
  const shape = document.getElementById('poolShape').value;
  const rectF = document.getElementById('rectFields');
  const circF = document.getElementById('circField');
  if (shape === 'circular') {
    rectF.style.display = 'none';
    circF.style.display = 'block';
    document.getElementById('poolLength').value = '';
    document.getElementById('poolWidth').value  = '';
  } else {
    rectF.style.display = 'grid';
    circF.style.display = 'none';
    document.getElementById('poolDiam').value = '';
  }
  calcVolume();
}

function calcVolume() {
  const shape = document.getElementById('poolShape').value;
  const depth = Math.max(0, parseFloat(document.getElementById('poolDepth').value) || 0);
  let vol = 0;
  let formulaNote = '';

  if (shape === 'circular') {
    const D = Math.max(0, parseFloat(document.getElementById('poolDiam').value) || 0);
    vol = (Math.PI / 4) * D * D * depth;
    formulaNote = `Circular: π/4 × ${D}² × ${depth} = ${vol.toFixed(1)} m³`;
  } else if (shape === 'oval') {
    const L = Math.max(0, parseFloat(document.getElementById('poolLength').value) || 0);
    const A = Math.max(0, parseFloat(document.getElementById('poolWidth').value)  || 0);
    vol = L * A * depth * 0.89;
    formulaNote = `Ovalada: ${L} × ${A} × ${depth} × 0.89 = ${vol.toFixed(1)} m³`;
  } else {
    const L = Math.max(0, parseFloat(document.getElementById('poolLength').value) || 0);
    const A = Math.max(0, parseFloat(document.getElementById('poolWidth').value)  || 0);
    vol = L * A * depth;
    formulaNote = `Rectangular: ${L} × ${A} × ${depth} = ${vol.toFixed(1)} m³`;
  }

  APP.volume = vol;
  const el  = document.getElementById('volValue');
  const elL = document.getElementById('volValueL');
  const elN = document.getElementById('calcFormulaNote');
  if (vol > 0) {
    if (el)  el.textContent  = vol.toFixed(1) + ' m³';
    if (elL) elL.textContent = Math.round(vol * 1000).toLocaleString('es-CO') + ' L';
    if (elN) elN.textContent = formulaNote;
  } else {
    if (el)  el.textContent  = '–';
    if (elL) elL.textContent = '–';
    if (elN) elN.textContent = 'Ingresa las dimensiones del estanque';
  }

  if (vol > 0) {
    const repVol = document.getElementById('repVolumen');
    if (repVol) { repVol.value = vol.toFixed(1); saveReportFields(); }
  }

  calcDosificacion();
}

// ── CALCULADORA: DOSIS ───────────────────────────────────
const PARAM_CONFIG = {
  cloro:       { label: 'Cloro libre residual', unit: 'ppm', range: 'Rango: 2–4 ppm',    min: 0,  max: 6,   normMin: 2.0, normMax: 4.0,  doseLabel: 'DOSIS RECOMENDADA · HIPOCLORITO DE CALCIO 70%',  doseUnit: 'g', note: 'Aplicar disuelto, con filtro encendido. Reevaluar a los 30 min.' },
  ph:          { label: 'pH',                   unit: '',    range: 'Rango: 6.8–7.3',    min: 6,  max: 9,   normMin: 6.8, normMax: 7.3,  doseLabel: 'AJUSTE DE pH',                                   doseUnit: '',  note: 'Subir pH: carbonato de sodio. Bajar pH: ácido muriático.' },
  alcalinidad: { label: 'Alcalinidad total',    unit: 'ppm', range: 'Rango: 20–150 ppm', min: 0,  max: 200, normMin: 20,  normMax: 150,  doseLabel: 'DOSIS RECOMENDADA · BICARBONATO DE SODIO',        doseUnit: 'g', note: 'Disolver antes de agregar. Reevaluar en 4–6 horas.' },
  cya:         { label: 'Estabilizador de cloro (CYA)', unit: 'ppm',range: 'Rango: 0–75 ppm', min: 0, max: 100, normMin: 0,   normMax: 75,   doseLabel: 'NIVEL DE ESTABILIZADOR (CYA)',                     doseUnit: 'ppm', note: 'Si supera 75 ppm, reemplazar parte del agua.' },
};

function switchParam(param, btn) {
  document.querySelectorAll('.param-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  APP.currentParam = param;

  const cfg = PARAM_CONFIG[param];
  const stored = JSON.parse(localStorage.getItem('aqua_calc') || '{}');
  const vals   = stored.paramValues?.[param];
  document.getElementById('paramActual').value = vals?.actual ?? '';
  document.getElementById('paramTarget').value = vals?.target ?? '';
  document.getElementById('calcGaugeLabel').textContent = cfg.label;
  document.getElementById('calcGaugeRange').textContent = cfg.range;
  document.getElementById('calcGaugeUnit').textContent  = cfg.unit;
  calcDose();
}

function saveCalcFields() {
  sessionStorage.setItem('aqua_calc_medicion', JSON.stringify({
    cloroActual:    document.getElementById('calcCloroActual')?.value    || '',
    cloroObj:       document.getElementById('calcCloroObj')?.value       || '3.0',
    phActual:       document.getElementById('calcPhActual')?.value       || '',
    phObj:          document.getElementById('calcPhObj')?.value          || '7.1',
    alcActual:      document.getElementById('calcAlcActual')?.value      || '',
    alcObj:         document.getElementById('calcAlcObj')?.value         || '100',
    cyaActual:      document.getElementById('calcCyaActual')?.value      || '',
    cyaObj:         document.getElementById('calcCyaObj')?.value         || '40',
    cloroCombActual:document.getElementById('calcCloroCombActual')?.value || '',
  }));
}

function restoreCalcFields() {
  updateShapeFields();
  const m = JSON.parse(sessionStorage.getItem('aqua_calc_medicion') || 'null');
  if (m) {
    const caEl  = document.getElementById('calcCloroActual');
    const coEl  = document.getElementById('calcCloroObj');
    const paEl  = document.getElementById('calcPhActual');
    const poEl  = document.getElementById('calcPhObj');
    const aaEl  = document.getElementById('calcAlcActual');
    const aoEl  = document.getElementById('calcAlcObj');
    const cyEl  = document.getElementById('calcCyaActual');
    const cyoEl = document.getElementById('calcCyaObj');
    const ccEl  = document.getElementById('calcCloroCombActual');
    if (caEl && m.cloroActual)     caEl.value  = m.cloroActual;
    if (coEl && m.cloroObj)        coEl.value  = m.cloroObj;
    if (paEl && m.phActual)        paEl.value  = m.phActual;
    if (poEl && m.phObj)           poEl.value  = m.phObj;
    if (aaEl && m.alcActual)       aaEl.value  = m.alcActual;
    if (aoEl && m.alcObj)          aoEl.value  = m.alcObj;
    if (cyEl  && m.cyaActual)      cyEl.value  = m.cyaActual;
    if (cyoEl && m.cyaObj)         cyoEl.value = m.cyaObj;
    if (ccEl  && m.cloroCombActual)ccEl.value  = m.cloroCombActual;
    calcDosificacion();
  }
}

function calcDose() {
  if (!document.getElementById('paramActual')) return;
  const param  = APP.currentParam;
  const cfg    = PARAM_CONFIG[param];
  const actual = parseFloat(document.getElementById('paramActual').value) || 0;
  const target = parseFloat(document.getElementById('paramTarget').value) || 0;
  const vol    = APP.volume || 0;
  if (!vol) {
    const dN = document.getElementById('doseNote');
    const dV = document.getElementById('doseValue');
    if (dN) dN.textContent = 'Ingresa las dimensiones del estanque en el Paso 1.';
    if (dV) dV.textContent = '–';
    saveCalcFields();
    return;
  }
  const delta  = target - actual;

  // Gauge mini
  const cumple = actual >= cfg.normMin && actual <= cfg.normMax;
  const color  = cumple ? '#0cb86a' : '#f59e0b';
  drawGauge('calcGauge', actual, cfg.min, cfg.max, color);
  const numEl = document.getElementById('calcGaugeNum');
  if (numEl) { numEl.textContent = actual; numEl.style.color = color; }

  // Dosis
  let doseText = '–';
  let note = cfg.note;

  if (delta > 0) {
    if (param === 'cloro') {
      doseText = (delta * vol * 1.43).toFixed(0) + ' g';
    } else if (param === 'alcalinidad') {
      doseText = (delta * vol * 1.68).toFixed(0) + ' g';
    } else if (param === 'ph') {
      doseText = (delta * vol * 22).toFixed(0) + ' g carbonato de sodio';
    } else {
      doseText = actual + ' ppm (leer nota)';
    }
  } else if (delta < 0) {
    if (param === 'ph') {
      doseText = (Math.abs(delta) * vol * 15).toFixed(0) + ' ml ácido muriático';
    } else {
      doseText = 'Dilución necesaria';
    }
  } else {
    doseText = 'En rango óptimo';
  }

  const doseHeader = document.getElementById('doseHeader');
  const doseValue  = document.getElementById('doseValue');
  const doseNote   = document.getElementById('doseNote');
  if (doseHeader) doseHeader.textContent = cfg.doseLabel;
  if (doseValue)  doseValue.textContent  = doseText;
  if (doseNote)   doseNote.textContent   = note;

  saveCalcFields();
}

// ── CALCULADORA: NUEVA DOSIFICACIÓN ──────────────────────
function _fmtMass(g) {
  if (g >= 1000000) return (g / 1000000).toFixed(2) + ' t';
  if (g >= 1000) {
    const kg = g / 1000;
    if (kg >= 10) return kg.toFixed(1) + ' kg';
    return kg.toFixed(2) + ' kg';
  }
  return Math.round(g) + ' g';
}
function _fmtVol(ml) {
  if (ml >= 1000000) return (ml / 1000000).toFixed(2) + ' m³';
  if (ml >= 1000) {
    const L = ml / 1000;
    if (L >= 10) return L.toFixed(1) + ' L';
    return L.toFixed(2) + ' L';
  }
  return Math.round(ml) + ' ml';
}

function _buildChems(chems) {
  return `<div class="calc-chemicals">${chems.map(c => `
    <div class="calc-chem-opt${c.urgent ? ' calc-chem-urgent' : ''}">
      <div class="calc-chem-name">${c.name}</div>
      <div class="calc-chem-dose">${c.dose}</div>
      <div class="calc-chem-formula">${c.formula}</div>
      ${c.warning ? `<div class="calc-chem-warning">${c.warning}</div>` : ''}
    </div>`).join('')}</div>`;
}

function _buildCalcBlock(o) {
  const noAction = o.inRange
    ? `<div class="calc-noaction"><svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#0cb86a" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
       <span>Dentro del rango Res. 234/2026 (<strong>${o.rangeText}</strong>) · Sin acción requerida.</span></div>` : '';
  const closure = o.closureAlert
    ? `<div class="calc-closure-alert"><svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
       <div><strong>Piscina cerrada al público</strong> · Art. 6, Res. 234/2026<br>
       Cloro libre supera el máximo permitido de 4.0 ppm. No permitir acceso hasta normalizar.</div></div>` : '';
  const art5 = o.showArt5
    ? `<div class="calc-art5-note"><svg aria-hidden="true" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
       Art. 5 · Res. 234/2026: No realizar dosificaciones manuales con público en el agua.</div>` : '';
  return `<div class="calc-result-block">
    <div class="calc-result-header">
      <span class="calc-result-title">${o.title}</span>
      <span class="calc-result-badge ${o.badgeCls}">${o.badge}</span>
    </div>
    <div class="calc-readings">
      <span>Actual: <strong>${o.actual}</strong></span>
      <span class="calc-arr">→</span>
      <span>Objetivo: <strong>${o.target}</strong></span>
      ${!o.inRange ? `<span class="calc-delta">Δ ${o.delta}</span>` : ''}
    </div>
    ${closure}${noAction}${o.body || ''}${art5}
  </div>`;
}

function _calcPhBlock(vol, p, r) {
  const { PMIN, PMAX, phOk } = r;
  const diff = p.phT - p.phA;
  const abs  = Math.abs(diff);
  let body = '';
  if (!phOk) {
    const phNote = `<div class="calc-ph-alknote">
      <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#92400e" stroke-width="2" style="flex-shrink:0;margin-top:1px"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      <span><strong>Dosis de inicio conservadora.</strong> La cantidad real depende de la alcalinidad total (AT) del agua: a mayor AT, mayor resistencia al cambio de pH. Verifica el resultado siempre tras 4–6 h de circulación antes de volver a dosar.</span>
    </div>`;
    if (p.phA < PMIN) {
      body = phNote + _buildChems([
        { name: 'Carbonato de sodio (Na₂CO₃)', dose: _fmtMass(abs * vol * 22), formula: `${vol.toFixed(1)} m³ × ${abs.toFixed(2)} ΔpH × 22 g/m³`, warning: 'A alcalinidad > 100 ppm puede requerirse el doble o más. Usa la pestaña Alcalinidad para ajustar AT primero si supera 150 ppm.' },
      ]);
    } else {
      const mlHCl = abs * vol * 15;
      body = phNote + _buildChems([
        { name: 'Ácido muriático HCl 31%', dose: _fmtVol(mlHCl), formula: `${vol.toFixed(1)} m³ × ${abs.toFixed(2)} ΔpH × 15 ml/m³`,
          warning: (mlHCl > 7000 ? '⚠ Supera 7 L — aplicar en varias dosis separadas. Máx. 7–8 L por aplicación. ' : '') + 'A 80–120 ppm de AT puede necesitarse hasta 5–8× esta cifra. Para correcciones > 0.5 pH, reduce primero la AT con ácido (pestaña Alcalinidad: 2.03 ml/m³·ppm) antes de reajustar pH.' },
        { name: 'Bisulfato de sodio (NaHSO₄)', dose: _fmtMass(abs * vol * 18), formula: `${vol.toFixed(1)} m³ × ${abs.toFixed(2)} ΔpH × 18 g/m³` },
      ]);
    }
  }
  return _buildCalcBlock({
    title: 'Ajuste de pH', inRange: phOk, rangeText: `${PMIN}–${PMAX}`,
    actual: String(p.phA), target: String(p.phT), delta: diff.toFixed(2),
    badge: phOk ? 'En rango ✓' : (p.phA < PMIN ? `Bajo · pH ${p.phA}` : `Alto · pH ${p.phA}`),
    badgeCls: phOk ? 'calc-badge-ok' : (p.phA < PMIN ? 'calc-badge-warning' : 'calc-badge-danger'),
    body, showArt5: !phOk,
  });
}

function _calcCloroBlock(vol, p, r) {
  const { CMIN, CMAX, cloroOk } = r;
  const diff = p.cloroT - p.cloroA;
  const abs  = Math.abs(diff);
  const over = p.cloroA > CMAX;
  let body = '';
  if (!cloroOk) {
    if (over) {
      body = _buildChems([
        { name: 'Tiosulfato de sodio (Na₂S₂O₃) — solo urgente', dose: _fmtMass(abs * vol * 3.5),
          formula: `${vol.toFixed(1)} m³ × ${abs.toFixed(2)} Δppm × 3.5 g/m³`,
          warning: 'Alternativa preferible: dilución con agua fresca y aguardar disipación natural.', urgent: true },
      ]);
    } else {
      body = _buildChems([
        { name: 'Hipoclorito de calcio 70% (granulado/pastilla)', dose: _fmtMass(abs * vol * 1.43), formula: `${vol.toFixed(1)} m³ × ${abs.toFixed(2)} Δppm × 1.43 g/m³` },
        { name: 'Hipoclorito de sodio 15% (líquido)', dose: _fmtVol(abs * vol * 5.78), formula: `${vol.toFixed(1)} m³ × ${abs.toFixed(2)} Δppm × 5.78 ml/m³`, warning: 'Factor para NaClO al 15% en masa (densidad ≈ 1.21 g/mL). Si la etiqueta indica "15% de cloro activo disponible" o "150 g Cl₂/L" (convención común en productos colombianos para piscinas), use 6.67 ml/m³·ppm (≈ 21% más). Blanqueador doméstico (2–5%) requiere entre 3× y 7× más volumen.' },
      ]);
    }
  }
  return _buildCalcBlock({
    title: 'Cloro libre residual', inRange: cloroOk, rangeText: `${CMIN}–${CMAX} ppm`,
    actual: p.cloroA + ' ppm', target: p.cloroT + ' ppm', delta: diff.toFixed(2) + ' ppm',
    badge: cloroOk ? 'En rango ✓' : (over ? `Exceso · ${p.cloroA} ppm — CERRAR` : `Bajo · ${p.cloroA} ppm`),
    badgeCls: cloroOk ? 'calc-badge-ok' : 'calc-badge-danger',
    closureAlert: over, body, showArt5: !cloroOk && !over,
  });
}

function _calcCloroCombBlock(vol, p) {
  const ccOk = p.cloroCombA <= 0.3;
  let body = '';
  if (!ccOk) {
    const bpTarget    = +(p.cloroCombA * 10).toFixed(1);
    const actualCloro = isNaN(p.cloroA) ? 0 : p.cloroA;
    const bpDelta     = Math.max(0, bpTarget - actualCloro);
    if (bpDelta > 0) {
      body = _buildChems([
        { name: 'Hipoclorito de calcio 70%', dose: _fmtMass(bpDelta * vol * 1.43),
          formula: `${vol.toFixed(1)} m³ × ${bpDelta.toFixed(1)} Δppm × 1.43 g/m³`,
          warning: `Cloración de choque: elevar el cloro total a ${bpTarget} ppm (= 10 × ${p.cloroCombA} ppm combinado) para oxidar y eliminar el cloro combinado (cloraminas). Reapertura cuando cloro libre regrese a 2–4 ppm. No dosar con bañistas.` },
        { name: 'Hipoclorito de sodio 15%', dose: _fmtVol(bpDelta * vol * 5.78),
          formula: `${vol.toFixed(1)} m³ × ${bpDelta.toFixed(1)} Δppm × 5.78 ml/m³` },
      ]);
    } else {
      body = `<div class="calc-noaction" style="background:#fef3c7;border-color:#fde68a"><svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#92400e" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        El cloro libre actual (${actualCloro} ppm) ya supera el objetivo de cloración de choque (${bpTarget} ppm). Aguardar disipación natural.</div>`;
    }
  }
  return _buildCalcBlock({
    title: 'Cloro combinado', inRange: ccOk, rangeText: '≤ 0.3 ppm',
    actual: p.cloroCombA + ' ppm', target: '≤ 0.3 ppm', delta: (p.cloroCombA - 0.3).toFixed(2) + ' ppm',
    badge: ccOk ? 'En rango ✓' : `Exceso · ${p.cloroCombA} ppm`,
    badgeCls: ccOk ? 'calc-badge-ok' : 'calc-badge-danger',
    body, showArt5: !ccOk,
  });
}

function _calcAlcBlock(vol, p, r) {
  const { AMIN, AMAX } = r;
  const alcOk = p.alcA >= AMIN && p.alcA <= AMAX;
  const diff  = p.alcT - p.alcA;
  const abs   = Math.abs(diff);
  let body = '';
  if (!alcOk) {
    if (p.alcA < AMIN) {
      body = _buildChems([
        { name: 'Bicarbonato de sodio (NaHCO₃)', dose: _fmtMass(abs * vol * 1.68),
          formula: `${abs.toFixed(0)} Δppm × ${vol.toFixed(1)} m³ × 1.68 g/m³`,
          warning: 'Disolver antes de agregar al agua. Reevaluar en 4–6 horas. No dosificar con bañistas.' },
      ]);
    } else {
      body = _buildChems([
        { name: 'Ácido muriático HCl 31%', dose: _fmtVol(abs * vol * 2.03),
          formula: `(${p.alcA} − ${p.alcT.toFixed(0)}) Δppm × ${vol.toFixed(1)} m³ × 2.03 mL/m³`,
          warning: 'Diluir en agua antes de agregar. Aplicar con bomba en circulación. No dosificar con bañistas. Reevaluar en 4–6 h.' },
      ]);
    }
  }
  return _buildCalcBlock({
    title: 'Alcalinidad total', inRange: alcOk, rangeText: `${AMIN}–${AMAX} ppm`,
    actual: p.alcA + ' ppm', target: p.alcT + ' ppm', delta: diff.toFixed(0) + ' ppm',
    badge: alcOk ? 'En rango ✓' : (p.alcA < AMIN ? `Baja · ${p.alcA} ppm` : `Alta · ${p.alcA} ppm`),
    badgeCls: alcOk ? 'calc-badge-ok' : 'calc-badge-warning',
    body, showArt5: !alcOk && p.alcA < AMIN,
  });
}

function _calcCyaBlock(vol, p, r) {
  const { CYAMAX } = r;
  const cyaOk = p.cyaA <= CYAMAX;
  let body = '';
  if (!cyaOk) {
    const vVaciar = vol * (1 - p.cyaT / p.cyaA);
    body = _buildChems([
      { name: 'Dilución con agua fresca', dose: `${vVaciar.toFixed(1)} m³ a vaciar`,
        formula: `${vol.toFixed(1)} × (1 − ${p.cyaT}/${p.cyaA})`,
        warning: `CYA en ${p.cyaA} ppm supera el máximo normativo (${CYAMAX} ppm). Vaciar aprox. ${vVaciar.toFixed(1)} m³ y reponer con agua sin estabilizador. No existe producto químico que elimine el CYA — la dilución es el único método confiable. Productos enzimáticos especiales ofrecen reducción parcial y lenta (alto costo).` },
    ]);
  }
  return _buildCalcBlock({
    title: 'Estabilizador (CYA)', inRange: cyaOk, rangeText: `0–${CYAMAX} ppm`,
    actual: p.cyaA + ' ppm', target: p.cyaT + ' ppm', delta: '',
    badge: !cyaOk ? `Exceso · ${p.cyaA} ppm` : 'En rango ✓',
    badgeCls: !cyaOk ? 'calc-badge-danger' : 'calc-badge-ok',
    body, showArt5: false,
  });
}

function calcDosificacion() {
  const resultEl = document.getElementById('calcResultados');
  if (!resultEl) return;
  saveCalcFields();

  const vol = APP.volume || 0;
  const p   = {
    cloroA:     parseFloat(document.getElementById('calcCloroActual')?.value),
    cloroT:     (v => isNaN(v) ? 3.0  : v)(parseFloat(document.getElementById('calcCloroObj')?.value)),
    phA:        parseFloat(document.getElementById('calcPhActual')?.value),
    phT:        (v => isNaN(v) ? 7.1  : v)(parseFloat(document.getElementById('calcPhObj')?.value)),
    alcA:       parseFloat(document.getElementById('calcAlcActual')?.value),
    alcT:       (v => isNaN(v) ? 100  : v)(parseFloat(document.getElementById('calcAlcObj')?.value)),
    cyaA:       parseFloat(document.getElementById('calcCyaActual')?.value),
    cyaT:       (v => isNaN(v) ? 40   : v)(parseFloat(document.getElementById('calcCyaObj')?.value)),
    cloroCombA: parseFloat(document.getElementById('calcCloroCombActual')?.value),
  };

  if (!vol) {
    resultEl.innerHTML = `<div class="calc-placeholder"><p>Ingresa las dimensiones del estanque en el <strong>Paso 1</strong> para calcular el volumen.</p></div>`;
    return;
  }
  if (isNaN(p.cloroA) && isNaN(p.phA) && isNaN(p.alcA) && isNaN(p.cyaA)) {
    resultEl.innerHTML = `<div class="calc-placeholder"><p>Ingresa las mediciones actuales del agua en el <strong>Paso 2</strong>.</p></div>`;
    return;
  }

  const CMIN = 2.0, CMAX = 4.0, PMIN = 6.8, PMAX = 7.3;
  const AMIN = 20,  AMAX = 150,  CYAMAX = 75;

  const targetErrors = [];
  if (!isNaN(p.cloroA) && (p.cloroT < CMIN || p.cloroT > CMAX))
    targetErrors.push(`Objetivo de cloro <strong>${p.cloroT} ppm</strong> fuera del rango permitido (${CMIN}–${CMAX} ppm) · Res. 234/2026`);
  if (!isNaN(p.phA) && (p.phT < PMIN || p.phT > PMAX))
    targetErrors.push(`Objetivo de pH <strong>${p.phT}</strong> fuera del rango permitido (${PMIN}–${PMAX}) · Res. 234/2026`);

  if (targetErrors.length) {
    resultEl.innerHTML = `<div class="calc-target-error">
      <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      <div><strong>Objetivo fuera del rango normativo</strong><br>${targetErrors.map(e => `<span>${e}</span>`).join('<br>')}<br><span class="calc-target-hint">Corrige el campo "Objetivo" al valor dentro del rango para calcular la dosificación.</span></div>
    </div>`;
    return;
  }

  const phOk    = !isNaN(p.phA)    && p.phA    >= PMIN && p.phA    <= PMAX;
  const cloroOk = !isNaN(p.cloroA) && p.cloroA >= CMIN && p.cloroA <= CMAX;
  const alcInRange = isNaN(p.alcA)       || (p.alcA >= AMIN && p.alcA <= AMAX);
  const cyaInRange = isNaN(p.cyaA)       || p.cyaA <= CYAMAX;
  const ccInRange  = isNaN(p.cloroCombA) || p.cloroCombA <= 0.3;

  if (!isNaN(p.phA) && !isNaN(p.cloroA) && phOk && cloroOk && alcInRange && cyaInRange && ccInRange) {
    resultEl.innerHTML = `<div class="calc-all-ok">
      <svg aria-hidden="true" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#0cb86a" stroke-width="2.5">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>
      </svg>
      <div><strong>Agua en estado óptimo · Sin acción requerida</strong><br>
      <span>pH ${p.phA} · Cloro ${p.cloroA} ppm — todos los parámetros dentro de los rangos Res. 234/2026.</span></div>
    </div>`;
    return;
  }

  const ranges = { CMIN, CMAX, PMIN, PMAX, AMIN, AMAX, CYAMAX, phOk, cloroOk };
  let html = '';
  if (!isNaN(p.phA))        html += _calcPhBlock(vol, p, ranges);
  if (!isNaN(p.cloroA))     html += _calcCloroBlock(vol, p, ranges);
  if (!isNaN(p.cloroCombA)) html += _calcCloroCombBlock(vol, p);
  if (!isNaN(p.alcA))       html += _calcAlcBlock(vol, p, ranges);
  if (!isNaN(p.cyaA))       html += _calcCyaBlock(vol, p, ranges);

  resultEl.innerHTML = html || `<p class="empty-state">Ingresa los valores actuales en el Paso 2.</p>`;
  resultEl.classList.remove('result-fresh');
  void resultEl.offsetWidth;
  resultEl.classList.add('result-fresh');
}

// ── LSI LANGELIER ─────────────────────────────────────────
// Tablas de coeficientes exactas — Anexo Técnico I, Res. 234/2026
const _LSI_TEMP = [
  [5,0.130],[10,0.257],[15,0.376],[17,0.422],[19,0.466],[20,0.487],[21,0.509],
  [22,0.520],[23,0.550],[24,0.570],[25,0.590],[26,0.610],[27,0.629],[28,0.648],
  [29,0.667],[30,0.685],[31,0.703],[32,0.721],[33,0.738],[34,0.755],[35,0.772],
  [36,0.789],[37,0.805],[38,0.820],
];
const _LSI_HARD = [
  [5,0.305],[10,0.606],[15,0.782],[25,1.004],[50,1.306],[75,1.482],[100,1.607],
  [125,1.704],[150,1.784],[175,1.851],[200,1.909],[225,1.960],[250,2.006],
  [275,2.047],[300,2.085],[350,2.152],[400,2.210],[450,2.261],[500,2.307],
  [550,2.348],[600,2.386],[650,2.421],[700,2.453],[800,2.511],
];
const _LSI_ALK = [
  [10,1.006],[20,1.307],[30,1.484],[35,1.551],[40,1.609],[45,1.660],[50,1.706],
  [55,1.747],[60,1.785],[65,1.820],[70,1.852],[75,1.882],[80,1.910],[85,1.937],
  [90,1.961],[95,1.985],[100,2.007],[105,2.028],[110,2.049],[120,2.087],
  [130,2.121],[140,2.154],[150,2.184],[200,2.309],
];

function _lsiInterp(table, v) {
  if (v <= table[0][0])              return table[0][1];
  if (v >= table[table.length-1][0]) return table[table.length-1][1];
  for (let i = 0; i < table.length - 1; i++) {
    if (v >= table[i][0] && v <= table[i+1][0]) {
      const t = (v - table[i][0]) / (table[i+1][0] - table[i][0]);
      return table[i][1] + t * (table[i+1][1] - table[i][1]);
    }
  }
  return table[table.length-1][1];
}

// ── LSI helpers ───────────────────────────────────────────
function _setLsiPBadge(id, ok, textOk, textOut) {
  const el = document.getElementById(id);
  if (!el) return;
  if (textOk === undefined) { el.textContent = ''; el.className = 'lsi-pbadge'; return; }
  el.textContent = ok ? textOk : textOut;
  el.className   = 'lsi-pbadge ' + (ok ? 'lsi-pbadge-ok' : 'lsi-pbadge-out');
}

const LSI_DEFAULTS  = { lsiPh: 7.2, lsiTemp: 27, lsiHard: 250, lsiAlk: 100 };
const IRAPI_DEFAULTS = { sliderMicro: 0, sliderCloro: 0, sliderAlk: 0, sliderOtros: 0 };
let _lsiFromBitacora = false;

function updateDefaultNotice(noticeId, defaults) {
  const notice = document.getElementById(noticeId);
  if (!notice) return;
  const isDefault = Object.entries(defaults).every(([id, def]) => {
    const el = document.getElementById(id);
    return el && parseFloat(el.value) === def;
  });
  notice.classList.toggle('default-notice-hidden', !isDefault);
}

function _lsiClearResult() {
  const notice = document.getElementById('lsiDefaultNotice');
  if (notice) notice.classList.add('default-notice-hidden');
  const valEl = document.getElementById('lsiValue');
  const stEl  = document.getElementById('lsiStatus');
  if (valEl) { valEl.textContent = '–'; valEl.style.color = ''; }
  if (stEl)  { stEl.textContent  = 'Sin datos'; stEl.style.color = 'var(--text-muted)'; }
  document.querySelectorAll('.lsi-leg-item').forEach(l => l.classList.remove('active-leg'));
  const diagEl = document.getElementById('lsiDiagnosis');
  if (diagEl) diagEl.innerHTML = '';
  ['lsiPhBadge','lsiTempBadge','lsiHardBadge','lsiAlkBadge'].forEach(id => _setLsiPBadge(id));
  const canvas = document.getElementById('lsiGaugeCanvas');
  if (canvas) canvas.getContext('2d').clearRect(0, 0, canvas.width, canvas.height);
  sessionStorage.removeItem('aqua_lsi_result');
  sessionStorage.removeItem('aqua_lsi_fields');
}

function calcLSI() {
  const _r = id => { const v = parseFloat(document.getElementById(id)?.value); return isNaN(v) ? null : v; };
  const pH   = _r('lsiPh');
  const temp = _r('lsiTemp');
  const hard = _r('lsiHard');
  const alk  = _r('lsiAlk');

  // Si algún campo está vacío → no calcular y ocultar aviso
  const lsiNotice = document.getElementById('lsiDefaultNotice');
  if (pH === null || temp === null || hard === null || alk === null) {
    if (lsiNotice) lsiNotice.classList.add('default-notice-hidden');
    _lsiClearResult();
    return;
  }
  // Aviso: desde bitácora → siempre oculto; manual → solo si coincide con defaults
  if (lsiNotice) {
    if (_lsiFromBitacora) {
      lsiNotice.classList.add('default-notice-hidden');
    } else {
      updateDefaultNotice('lsiDefaultNotice', LSI_DEFAULTS);
    }
  }

  // Coeficientes exactos de la Tabla Res. 234/2026: ISL = pH + CT + CD + CA − 12.1
  const CT = _lsiInterp(_LSI_TEMP, temp);
  const CD = _lsiInterp(_LSI_HARD, hard);
  const CA = _lsiInterp(_LSI_ALK,  alk);

  const lsi = +(pH + CT + CD + CA - 12.1).toFixed(2);

  document.getElementById('lsiValue').textContent = lsi.toFixed(2);

  let status = 'Equilibrada', color = '#0cb86a';
  const legend = document.querySelectorAll('.lsi-leg-item');
  legend.forEach(l => l.classList.remove('active-leg'));

  // Rango aceptable Res. 234/2026: -0.3 a +0.5 (asimétrico)
  if (lsi < -0.3) {
    status = 'Corrosiva'; color = '#ef4444';
    legend[0]?.classList.add('active-leg');
  } else if (lsi > 0.5) {
    status = 'Incrustante'; color = '#f59e0b';
    legend[2]?.classList.add('active-leg');
  } else {
    legend[1]?.classList.add('active-leg');
  }

  document.getElementById('lsiStatus').textContent  = status;
  document.getElementById('lsiStatus').style.color  = color;
  document.getElementById('lsiValue').style.color   = color;

  drawLSIGauge('lsiGaugeCanvas', lsi);

  // ── Badges de parámetros de entrada ──────────────────
  _setLsiPBadge('lsiPhBadge',   pH >= 6.8 && pH <= 7.3,       '✓', '✗ fuera');
  _setLsiPBadge('lsiTempBadge', temp <= 40,                    '✓', '✗ > 40°C');
  _setLsiPBadge('lsiHardBadge', hard >= 200 && hard <= 700,    '✓', '✗ fuera');
  _setLsiPBadge('lsiAlkBadge',  alk >= 20 && alk <= 150,       '✓', '✗ fuera');

  // ── Diagnóstico completo ──────────────────────────────
  const diagEl = document.getElementById('lsiDiagnosis');
  if (diagEl) {
    const phOk   = pH >= 6.8 && pH <= 7.3;
    const hardOk = hard >= 200 && hard <= 700;
    const alkOk  = alk >= 20  && alk <= 150;
    const tempOk = temp <= 40;
    const allOk  = phOk && hardOk && alkOk && tempOk;

    if (lsi < -0.3) {
      // ── Corrosiva ──
      const tips = [];
      if (pH < 6.8)   tips.push(`Subir pH — actual ${pH}, mínimo 6.8`);
      if (hard < 200) tips.push(`Subir dureza cálcica — actual ${hard} ppm, mínimo 200 ppm`);
      if (alk < 20)   tips.push(`Subir alcalinidad — actual ${alk} ppm, mínimo 20 ppm`);
      if (!tips.length) tips.push('Combinación de factores genera índice negativo. Revisar pH y alcalinidad.');
      diagEl.innerHTML = `<div class="lsi-diag-box" style="border-color:#ef444455;background:#ef444410">
        <div class="lsi-diag-title" style="color:#ef4444">
          <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          Agua corrosiva — puede dañar superficies, tuberías y equipos
        </div>
        <ul class="lsi-diag-list">${tips.map(t => `<li>${t}</li>`).join('')}</ul>
      </div>`;

    } else if (lsi > 0.5) {
      // ── Incrustante ──
      const tips = [];
      if (pH > 7.3)   tips.push(`Bajar pH — actual ${pH}, máximo 7.3`);
      if (alk > 150)  tips.push(`Bajar alcalinidad — actual ${alk} ppm, máximo 150 ppm`);
      if (hard > 700) tips.push(`Dureza cálcica muy alta — actual ${hard} ppm, máximo 700 ppm. Dilución parcial.`);
      if (temp > 40)  tips.push(`Temperatura excede el máximo — actual ${temp} °C, máx. 40 °C`);
      if (!tips.length) tips.push('Revisar pH y alcalinidad para reducir el índice.');
      diagEl.innerHTML = `<div class="lsi-diag-box" style="border-color:#f59e0b55;background:#f59e0b10">
        <div class="lsi-diag-title" style="color:#f59e0b">
          <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          Agua incrustante — puede formar sarro en tuberías y equipos
        </div>
        <ul class="lsi-diag-list">${tips.map(t => `<li>${t}</li>`).join('')}</ul>
      </div>`;

    } else if (!allOk) {
      // ── Equilibrado pero con parámetros fuera de su rango individual ──
      // Explicar qué parámetros se están compensando entre sí
      const elevando = [], reduciendo = [], corregir = [];
      if (pH > 7.3)   { elevando.push(`pH alto (${pH} > 7.3) eleva el ISL`);   corregir.push(`Bajar pH a 6.8–7.3`); }
      if (pH < 6.8)   { reduciendo.push(`pH bajo (${pH} < 6.8) reduce el ISL`); corregir.push(`Subir pH a 6.8–7.3`); }
      if (hard > 700) { elevando.push(`Dureza alta (${hard} ppm) eleva el ISL`); corregir.push(`Bajar dureza cálcica — dilución`); }
      if (hard < 200) { reduciendo.push(`Dureza baja (${hard} ppm) reduce el ISL`); corregir.push(`Subir dureza cálcica a 200–700 ppm`); }
      if (alk > 150)  { elevando.push(`Alcalinidad alta (${alk} ppm) eleva el ISL`); corregir.push(`Bajar alcalinidad a 20–150 ppm`); }
      if (alk < 20)   { reduciendo.push(`Alcalinidad baja (${alk} ppm) reduce el ISL`); corregir.push(`Subir alcalinidad a 20–150 ppm`); }
      if (temp > 40)  { elevando.push(`Temperatura alta (${temp} °C) eleva el ISL`); corregir.push(`Temperatura excede el máximo de 40 °C`); }

      const efectos = [...elevando, ...reduciendo];
      diagEl.innerHTML = `<div class="lsi-diag-box" style="border-color:#d9770655;background:#fffbeb">
        <div class="lsi-diag-title" style="color:#d97706">
          <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          ISL equilibrado por compensación — parámetros individuales fuera de rango
        </div>
        <p class="lsi-diag-note">El ISL ${lsi.toFixed(2)} es equilibrado, pero los siguientes factores se están compensando entre sí. Corregir cada uno individualmente:</p>
        <ul class="lsi-diag-list">${efectos.map(e => `<li>${e}</li>`).join('')}</ul>
        <ul class="lsi-diag-list lsi-diag-fix">${corregir.map(c => `<li>→ ${c}</li>`).join('')}</ul>
      </div>`;

    } else {
      // ── Todo en rango ──
      diagEl.innerHTML = '';
    }

    // Advertencias de valores fuera del rango de las tablas de coeficientes
    const tableWarnings = [];
    if (hard < 5)  tableWarnings.push(`Dureza cálcica ${hard} ppm — por debajo del mínimo de la tabla (5 ppm). El coeficiente CD se clampea a 0.305; el agua real puede ser más corrosiva de lo indicado. Eleve la dureza a mínimo 200 ppm (Res. 234/2026).`);
    if (alk  < 10) tableWarnings.push(`Alcalinidad ${alk} ppm — por debajo del mínimo de la tabla (10 ppm). El coeficiente CA se clampea a 1.006; el ISL puede subestimar la corrosividad. Eleve la alcalinidad a mínimo 20 ppm.`);

    if (tableWarnings.length && diagEl) {
      const wHtml = `<div class="lsi-diag-box" style="border-color:#ef444455;background:#ef444410;margin-bottom:8px">
        <div class="lsi-diag-title" style="color:#ef4444">
          <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          ISL no confiable — valor fuera del rango de la tabla de coeficientes
        </div>
        <ul class="lsi-diag-list">${tableWarnings.map(w => `<li>${w}</li>`).join('')}</ul>
      </div>`;
      diagEl.innerHTML = wHtml + diagEl.innerHTML;
    }
  }

  sessionStorage.setItem('aqua_lsi_fields', JSON.stringify({ ph: pH, temp, hard, alk }));
  sessionStorage.setItem('aqua_lsi_result',  JSON.stringify({ lsi, status }));
}

function restoreLSIFields() {
  const f = JSON.parse(sessionStorage.getItem('aqua_lsi_fields') || 'null');
  if (!f) return;
  if (f.ph   != null) document.getElementById('lsiPh').value   = f.ph;
  if (f.temp != null) document.getElementById('lsiTemp').value = f.temp;
  if (f.hard != null) document.getElementById('lsiHard').value = f.hard;
  if (f.alk  != null) document.getElementById('lsiAlk').value  = f.alk;
}

function calcLSIFromBitacora() {
  const entries = getLog();
  if (!entries.length) {
    showToast('Sin registros en la bitácora. Ingresa una medición primero.', 'warning');
    return;
  }

  const last  = entries[0];
  const ph    = (last.ph    != null && isFinite(last.ph))    ? +last.ph    : null;
  const temp  = (last.temp  != null && isFinite(last.temp))  ? +last.temp  : null;
  const alc   = (last.alc   != null && isFinite(last.alc))   ? +last.alc   : null;
  const hard  = _lastDureza();

  if (ph === null && temp === null && alc === null) {
    showToast('El último registro no contiene datos de pH, temperatura ni alcalinidad.', 'warning');
    return;
  }

  if (ph   !== null) { const el = document.getElementById('lsiPh');   el.value = ph;   clampInput(el, 0, 14);  }
  if (temp !== null) { const el = document.getElementById('lsiTemp'); el.value = temp; clampInput(el, 0, 40);  }
  if (alc  !== null) { const el = document.getElementById('lsiAlk');  el.value = alc;  clampInput(el, 0, 200); }
  { const el = document.getElementById('lsiHard'); el.value = hard; clampInput(el, 0, 700); }

  _lsiFromBitacora = true;
  calcLSI();

  const parts = [];
  if (ph   !== null) parts.push(`pH ${ph}`);
  if (temp !== null) parts.push(`T ${temp} °C`);
  if (alc  !== null) parts.push(`Alc ${alc} ppm`);
  parts.push(`Dur ${hard} ppm`);
  showToast(`Cargado desde bitácora (${last.fecha}): ${parts.join(' · ')}`, 'success');
}

// ── IRAPI 2026 ────────────────────────────────────────────

function hasTrimestreData() {
  const log = getLog();
  if (log.length < 10) return false;
  const dates = log.map(e => +new Date(e.fecha + 'T00:00:00')).filter(d => !isNaN(d));
  if (dates.length < 2) return false;
  return (Math.max(...dates) - Math.min(...dates)) / 86400000 >= 30;
}

function _diasParaTrimestre() {
  const log = getLog();
  if (!log.length) return 90;
  const oldest = new Date(log[log.length - 1].fecha + 'T00:00:00');
  const today  = new Date(); today.setHours(0, 0, 0, 0);
  return Math.max(0, 90 - Math.floor((today - oldest) / 86400000));
}

function calcIRAPI() {
  updateDefaultNotice('irapiDefaultNotice', IRAPI_DEFAULTS);

  const hasEnough = hasTrimestreData();
  const IDS = ['sliderMicro','sliderCloro','sliderAlk','sliderOtros'];

  if (!hasEnough) {
    IDS.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.value = 0;
      el.disabled = true;
      el.style.setProperty('--pct', '0%');
    });
    ['valMicro','valCloro','valAlk','valOtros'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = '0%';
    });
    const bar = document.getElementById('irapiBarFill');
    if (bar) { bar.style.width = '0%'; bar.style.background = '#94a3b8'; }
    const scoreLbl = document.getElementById('irapiScoreLabel');
    if (scoreLbl) { scoreLbl.textContent = '–'; scoreLbl.style.color = '#94a3b8'; }
    document.querySelectorAll('.irapi-range-item').forEach(el => el.classList.remove('active-range'));
    const actionEl = document.getElementById('irapiAction');
    if (actionEl) {
      const faltan = _diasParaTrimestre();
      const log = getLog();
      const primerReg = log.length ? ` · Primer registro: ${log[log.length - 1].fecha}` : '';
      actionEl.textContent = `El IRAPI se calcula trimestralmente (Art. 9, Res. 234/2026). Faltan ${faltan} día${faltan !== 1 ? 's' : ''} para completar el trimestre${primerReg}.`;
      actionEl.className = 'irapi-action-phrase';
    }
    sessionStorage.removeItem('aqua_irapi_result');
    sessionStorage.removeItem('aqua_irapi_sliders');
    return;
  }

  IDS.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.disabled = false;
  });

  const micro = parseInt(document.getElementById('sliderMicro').value) || 0;
  const cloro = parseInt(document.getElementById('sliderCloro').value) || 0;
  const alk   = parseInt(document.getElementById('sliderAlk').value)   || 0;
  const otros = parseInt(document.getElementById('sliderOtros').value) || 0;

  document.getElementById('valMicro').textContent = micro + '%';
  document.getElementById('valCloro').textContent = cloro + '%';
  document.getElementById('valAlk').textContent   = alk   + '%';
  document.getElementById('valOtros').textContent = otros + '%';

  ['sliderMicro','sliderCloro','sliderAlk','sliderOtros'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.setProperty('--pct', el.value + '%');
  });

  const score = +(micro * 0.45 + cloro * 0.20 + alk * 0.30 + otros * 0.05).toFixed(1);

  const bar = document.getElementById('irapiBarFill');
  if (bar) bar.style.width = Math.min(score, 100) + '%';

  let label = 'Sin riesgo', color = '#0cb86a', cls = 'sin-riesgo';
  if (score > 75)      { label = 'Alto';  color = '#ef4444'; cls = 'alto'; }
  else if (score > 35) { label = 'Medio'; color = '#ea580c'; cls = 'medio'; }
  else if (score > 10) { label = 'Bajo';  color = '#d97706'; cls = 'bajo'; }

  const scoreLbl = document.getElementById('irapiScoreLabel');
  if (scoreLbl) { scoreLbl.textContent = label; scoreLbl.style.color = color; }
  if (bar) bar.style.background = color;

  document.querySelectorAll('.irapi-range-item').forEach(el => el.classList.remove('active-range'));
  const active = document.querySelector('.irapi-range-item.' + cls);
  if (active) active.classList.add('active-range');

  // Frase de acción según factor dominante
  const contributions = [
    { key: 'micro', val: micro * 0.45 },
    { key: 'alk',   val: alk   * 0.30 },
    { key: 'cloro', val: cloro * 0.20 },
    { key: 'otros', val: otros * 0.05 },
  ];
  const dominant = contributions.reduce((a, b) => b.val > a.val ? b : a).key;
  const ACTION_BAJO = {
    micro: 'Factor microbiológico activo. Programa análisis de laboratorio esta semana.',
    cloro: 'Nivel de cloro fuera del rango ideal. Ajusta la dosificación antes de la próxima sesión.',
    alk:   'pH, ORP o CYA con margen de riesgo. Verifica y corrige antes de la próxima medición.',
    otros: 'Factores adicionales elevan el riesgo. Revisa novedades registradas en la bitácora.',
  };
  const ACTION_MEDIO = {
    micro: 'Riesgo microbiológico moderado. Programa análisis de laboratorio urgente y refuerza la desinfección.',
    cloro: 'Cloro en nivel de alerta. Corrige la dosificación antes de la próxima sesión de uso.',
    alk:   'pH, ORP o CYA en rango de riesgo medio. Ajusta la química del agua hoy.',
    otros: 'Factores adicionales en alerta. Revisa novedades y aplica acciones correctivas.',
  };
  const ACTION_ALTO = {
    micro: 'Riesgo microbiológico alto. Solicita análisis de laboratorio urgente y considera cierre preventivo.',
    cloro: 'Cloro en nivel crítico. Ajusta la dosificación de inmediato y restringe el acceso hasta normalizar.',
    alk:   'pH, ORP o CYA en nivel crítico. Corrige la química del agua hoy — afecta directamente la eficacia del cloro.',
    otros: 'Múltiples factores de riesgo activos. Evalúa cierre preventivo y revisa todos los parámetros.',
  };
  let phrase = '';
  if (cls === 'sin-riesgo') {
    const allZero = micro === 0 && cloro === 0 && alk === 0 && otros === 0;
    phrase = allZero
      ? 'Ajusta los porcentajes de cumplimiento según tus registros trimestrales para calcular el IRAPI real.'
      : 'Agua en condiciones óptimas. Mantén el monitoreo diario según Res. 234/2026.';
  }
  else if (cls === 'bajo')  phrase = ACTION_BAJO[dominant];
  else if (cls === 'medio') phrase = ACTION_MEDIO[dominant];
  else                      phrase = ACTION_ALTO[dominant];

  const actionEl = document.getElementById('irapiAction');
  if (actionEl) {
    actionEl.textContent = phrase;
    actionEl.className   = 'irapi-action-phrase irapi-action-' + cls;
  }

  // Persistir valores y score
  sessionStorage.setItem('aqua_irapi_sliders', JSON.stringify({ micro, cloro, alk, otros }));
  sessionStorage.setItem('aqua_irapi_result',  JSON.stringify({ score, label }));
}

function hideMicroReminder() {
  const el = document.getElementById('microLabReminder');
  if (el) el.hidden = true;
}

function applyMicroLab() {
  const val = Math.min(100, Math.max(0, parseInt(document.getElementById('microLabValue').value) || 0));
  document.getElementById('sliderMicro').value = val;
  hideMicroReminder();
  calcIRAPI();
}

function restoreIRAPISliders() {
  if (!hasTrimestreData()) {
    sessionStorage.removeItem('aqua_irapi_sliders');
    sessionStorage.removeItem('aqua_irapi_result');
  } else {
    try {
      const s = JSON.parse(sessionStorage.getItem('aqua_irapi_sliders'));
      if (s) {
        document.getElementById('sliderMicro').value = s.micro;
        document.getElementById('sliderCloro').value = s.cloro;
        document.getElementById('sliderAlk').value   = s.alk;
        document.getElementById('sliderOtros').value = s.otros;
      }
    } catch {}
  }

}

function updateIRAPIBitacoraBtn() {
  const btn  = document.getElementById('btnCalcIRAPIBitacora');
  const note = document.getElementById('irapibitacoraNote');
  if (!btn) return;
  const ready = hasTrimestreData();
  const log   = getLog();
  btn.disabled = !ready;
  if (note) {
    if (ready) {
      note.textContent = `${log.length} registro${log.length !== 1 ? 's' : ''} disponibles · Microbiológico requiere laboratorio certificado.`;
    } else {
      const count = log.length;
      if (!count) {
        note.textContent = 'Sin registros en la bitácora. Agrega mediciones para habilitar el cálculo automático.';
      } else {
        const dates    = log.map(e => +new Date(e.fecha + 'T00:00:00')).filter(d => !isNaN(d));
        const spanDays = dates.length >= 2
          ? Math.round((Math.max(...dates) - Math.min(...dates)) / 86400000)
          : 0;
        note.textContent = `${count} de 10 registros · ${spanDays} de 30 días requeridos · Sigue registrando para habilitar.`;
      }
    }
  }
}

function calcIRAPIFromBitacora() {
  if (!hasTrimestreData()) return;

  const log = getLog();
  if (!log.length) return;

  const total   = log.length;
  const ncCloro = log.filter(e =>
    (e.cloro != null && !isNaN(e.cloro) && (e.cloro < 2.0 || e.cloro > 4.0)) ||
    (e.clorocomb != null && !isNaN(e.clorocomb) && e.clorocomb > 0.3)
  ).length;
  // VAC (Res. 234/2026 Anexo II): pH + ORP + Ácido Cianúrico
  const ncAlk   = log.filter(e =>
    (e.ph   != null && !isNaN(e.ph)   && (e.ph  < 6.8 || e.ph  > 7.3)) ||
    (e.orp  != null && !isNaN(e.orp)  && (e.orp < 650 || e.orp > 700)) ||
    (e.cya  != null && !isNaN(e.cya)  && e.cya  > 75)
  ).length;
  // VCT (Res. 234/2026 Anexo II): Turbiedad únicamente
  const ncOtros = log.filter(e =>
    (e.turb != null && !isNaN(e.turb) && e.turb > 0.5)
  ).length;

  const pctCloro = Math.round((ncCloro / total) * 100);
  const pctAlk   = Math.round((ncAlk   / total) * 100);
  const pctOtros = Math.round((ncOtros / total) * 100);

  // Microbiológico no se puede derivar de la bitácora: se deja en 0 (requiere laboratorio)
  document.getElementById('sliderMicro').value = 0;
  document.getElementById('sliderCloro').value = pctCloro;
  document.getElementById('sliderAlk').value   = pctAlk;
  document.getElementById('sliderOtros').value = pctOtros;

  ['tagCloro', 'tagAlk', 'tagOtros'].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.textContent = `Auto (${total} reg.)`; el.style.display = 'inline'; }
  });

  calcIRAPI();
  const reminder = document.getElementById('microLabReminder');
  if (reminder) reminder.hidden = false;
  showToast(`IRAPI calculado desde ${total} registro${total !== 1 ? 's' : ''} de la bitácora. Ingresa el resultado microbiológico manualmente.`, 'info');
}

// ── BITÁCORA ──────────────────────────────────────────────
function updateOperadorDatalist() {
  const dl = document.getElementById('operadorList');
  if (!dl) return;
  const names = [...new Set(
    getLog().map(e => e.operador).filter(n => n && n.trim())
  )].sort();
  dl.innerHTML = names.map(n => `<option value="${escapeHtml(n)}"></option>`).join('');
}

// ── Validadores de esquema ────────────────────────────────
function _isValidLogEntry(e) {
  return e !== null && typeof e === 'object'
    && typeof e.ts    === 'number' && isFinite(e.ts)
    && typeof e.fecha === 'string' && e.fecha.length > 0
    && typeof e.hora  === 'string'
    && isFinite(Number(e.cloro))
    && isFinite(Number(e.ph))
    && isFinite(Number(e.alc))
    && isFinite(Number(e.turb))
    && isFinite(Number(e.temp));
}

function _isValidAFREntry(e) {
  return e !== null && typeof e === 'object'
    && typeof e.ts    === 'number' && isFinite(e.ts)
    && ['solido', 'vomito', 'diarreico'].includes(e.tipo)
    && typeof e.fecha === 'string' && e.fecha.length > 0;
}

function getLog() {
  if (!_requireUnlocked()) return [];
  try {
    const raw = JSON.parse(localStorage.getItem('aqua_bitacora')) || [];
    return Array.isArray(raw) ? raw.filter(_isValidLogEntry) : [];
  }
  catch { return []; }
}

const LOG_REQUIRED = ['logDate','logTime','logCloro','logCloroComb','logPh','logAlc','logTurb','logTemp'];
let editingLogTs = null;
let editingMntTs = null;
let _newLogTs    = 0;
let _trendParam  = 'cloro';
let _trendDays   = 7;

// Rangos Res. 234/2026 para cada campo de bitácora
const LOG_PARAM_RANGES = [
  { id: 'logCloro',     badge: 'logCloroBadge',     min: 2.0, max: 4.0  },
  { id: 'logCloroComb', badge: 'logCloroCombBadge', min: 0,   max: 0.3  },
  { id: 'logPh',        badge: 'logPhBadge',        min: 6.8, max: 7.3  },
  { id: 'logAlc',       badge: 'logAlcBadge',       min: 20,  max: 150  },
  { id: 'logDureza',   badge: 'logDurezaBadge',    min: 200, max: 700  },
  { id: 'logCya',       badge: 'logCyaBadge',       min: 0,   max: 75   },
  { id: 'logTurb',      badge: 'logTurbBadge',      min: 0,   max: 0.5  },
  { id: 'logTemp',      badge: 'logTempBadge',      min: 0,   max: 40   },
  { id: 'logOrp',       badge: 'logOrpBadge',       min: 0,    max: 700, warnBelow: 650 },
  { id: 'logTds',       badge: 'logTdsBadge',       min: 1000, max: 1200 },
  { id: 'logCond',      badge: 'logCondBadge',      min: 2000, max: 2400 },
];

function checkLogForm() {
  const ok = LOG_REQUIRED.every(id => {
    const el = document.getElementById(id);
    return el && el.value.trim() !== '';
  });
  const btn = document.getElementById('btnSaveLog');
  if (btn) btn.disabled = !ok;

  // Actualizar semáforos y barra de cumplimiento
  let filled = 0, outRange = 0;
  LOG_PARAM_RANGES.forEach(f => {
    const el    = document.getElementById(f.id);
    const badge = document.getElementById(f.badge);
    if (!el || !badge) return;
    const v = parseFloat(el.value);
    if (isNaN(v) || el.value === '') {
      badge.textContent = ''; badge.className = 'lsi-pbadge'; return;
    }
    filled++;
    const inRange = v >= f.min && v <= f.max;
    if (!inRange) outRange++;
    const isWarn = inRange && f.warnBelow !== undefined && v < f.warnBelow;
    badge.textContent = inRange ? (isWarn ? '⚠ eficacia' : '✓') : '✗ fuera';
    badge.className   = 'lsi-pbadge ' + (inRange ? (isWarn ? 'lsi-pbadge-warn' : 'lsi-pbadge-ok') : 'lsi-pbadge-out');
  });

  const bar = document.getElementById('logComplianceBar');
  if (!bar) return;
  if (filled === 0) { bar.style.display = 'none'; return; }
  bar.style.display = 'flex';
  if (outRange === 0) {
    bar.className = 'log-compliance-bar log-comp-ok';
    bar.innerHTML = `<svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
      Todos los parámetros dentro del rango &nbsp;·&nbsp; Res. 234/2026`;
  } else {
    bar.className = 'log-compliance-bar log-comp-out';
    bar.innerHTML = `<svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
      <strong>${outRange} de ${filled} par&aacute;metro${outRange > 1 ? 's' : ''} fuera del rango</strong> &nbsp;·&nbsp; Res. 234/2026 &nbsp;&middot;&nbsp; El registro se guardar&aacute; igual.`;
  }
}

function _lastDureza() {
  const found = getLog().find(e => e.dureza != null && isFinite(e.dureza));
  return found ? +found.dureza : 250;
}

// ── FOTOS ─────────────────────────────────────────────────
const _photos = { fotoAgua: null, fotoAveria: null, afrFoto: null, mantenimientoFoto: null };
let _photoPickerActive  = false;
let _rotationOffered    = false;

function triggerPhoto(key) {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = 'image/*';
  input.capture = 'environment';
  input.onchange = e => {
    _photoPickerActive = false;
    const file = e.target.files[0];
    if (!file) return;
    _compressPhoto(file, b64 => _applyPhoto(key, b64));
  };
  _photoPickerActive = true;
  input.click();
}

function removePhoto(key) { _applyPhoto(key, null); }

function _applyPhoto(key, b64) {
  _photos[key] = b64;
  const wrap  = document.getElementById('photo-preview-' + key);
  const thumb = document.getElementById('photo-thumb-'   + key);
  if (!wrap || !thumb) return;
  wrap.hidden = !b64;
  thumb.src   = b64 || '';
}

function _compressPhoto(file, cb) {
  const img = new Image();
  const url = URL.createObjectURL(file);
  img.onload = () => {
    URL.revokeObjectURL(url);
    const MAX = 600;
    let w = img.width, h = img.height;
    if (w > MAX || h > MAX) {
      if (w > h) { h = Math.round(h * MAX / w); w = MAX; }
      else       { w = Math.round(w * MAX / h); h = MAX; }
    }
    const canvas = document.createElement('canvas');
    canvas.width = w; canvas.height = h;
    canvas.getContext('2d').drawImage(img, 0, 0, w, h);
    cb(canvas.toDataURL('image/jpeg', 0.72));
  };
  img.src = url;
}

function clearLogForm() {
  const now  = new Date();
  document.getElementById('logDate').value      = localDateStr(now);
  document.getElementById('logTime').value      = now.toTimeString().slice(0, 5);
  document.getElementById('logOperador').value  = '';
  document.getElementById('logCloro').value     = '';
  document.getElementById('logCloroComb').value = '';
  document.getElementById('logPh').value        = '';
  document.getElementById('logAlc').value       = '';
  document.getElementById('logCya').value       = '';
  document.getElementById('logTurb').value      = '';
  document.getElementById('logTemp').value      = '';
  document.getElementById('logDureza').value    = '';
  document.getElementById('logBanistas').value  = '';
  document.getElementById('logOrp').value       = '';
  document.getElementById('logTds').value       = '';
  document.getElementById('logCond').value      = '';
  document.getElementById('logCaudal').value    = '';
  document.getElementById('logHorasFun').value  = '';
  document.getElementById('logAguaRep').value   = '';
  document.getElementById('logRetrolav').value  = '';
  document.getElementById('logProdQuim').value  = '';
  document.getElementById('logAverias').value   = '';
  document.getElementById('logNotas').value     = '';
  _applyPhoto('fotoAgua',   null);
  _applyPhoto('fotoAveria', null);
  checkLogForm();
}

function editLog(ts) {
  const entry = getLog().find(e => e.ts === ts);
  if (!entry) return;
  editingLogTs = ts;
  document.getElementById('logDate').value      = entry.fecha     || '';
  document.getElementById('logTime').value      = entry.hora      || '';
  document.getElementById('logOperador').value  = entry.operador  || '';
  document.getElementById('logCloro').value     = entry.cloro     ?? '';
  document.getElementById('logCloroComb').value = entry.clorocomb ?? '';
  document.getElementById('logPh').value        = entry.ph        ?? '';
  document.getElementById('logAlc').value       = entry.alc       ?? '';
  document.getElementById('logCya').value       = entry.cya       ?? '';
  document.getElementById('logTurb').value      = entry.turb      ?? '';
  document.getElementById('logTemp').value      = entry.temp      ?? '';
  document.getElementById('logDureza').value    = entry.dureza    ?? '';
  document.getElementById('logBanistas').value  = entry.banistas  ?? '';
  document.getElementById('logOrp').value       = entry.orp       ?? '';
  document.getElementById('logTds').value       = entry.tds       ?? '';
  document.getElementById('logCond').value      = entry.cond      ?? '';
  document.getElementById('logCaudal').value    = entry.caudal    ?? '';
  document.getElementById('logHorasFun').value  = entry.horasFun  ?? '';
  document.getElementById('logAguaRep').value   = entry.aguaRep   ?? '';
  document.getElementById('logRetrolav').value  = entry.retrolav  ?? '';
  document.getElementById('logProdQuim').value  = entry.prodQuim  || '';
  document.getElementById('logAverias').value   = entry.averias   || '';
  document.getElementById('logNotas').value     = entry.notas     || '';
  _applyPhoto('fotoAgua',   entry.fotoAgua   || null);
  _applyPhoto('fotoAveria', entry.fotoAveria || null);
  document.getElementById('btnSaveLogText').textContent   = 'Actualizar registro';
  document.getElementById('logEditDate').textContent      = entry.fecha || '';
  document.getElementById('logEditBanner').style.display  = 'flex';
  document.getElementById('btnCancelEdit').style.display  = 'inline-flex';
  checkLogForm();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function cancelEditLog() {
  editingLogTs = null;
  document.getElementById('btnSaveLogText').textContent   = 'Guardar en bitácora';
  document.getElementById('logEditBanner').style.display  = 'none';
  document.getElementById('btnCancelEdit').style.display  = 'none';
  clearLogForm();
}

function _buildLogEntry() {
  const banistasRaw = parseInt(document.getElementById('logBanistas').value);
  const orpRaw      = parseFloat(document.getElementById('logOrp').value);
  const tdsRaw      = parseFloat(document.getElementById('logTds').value);
  const condRaw     = parseFloat(document.getElementById('logCond').value);
  const caudalRaw   = parseFloat(document.getElementById('logCaudal').value);
  const horasFunRaw = parseFloat(document.getElementById('logHorasFun').value);
  const aguaRepRaw  = parseFloat(document.getElementById('logAguaRep').value);
  const retrolavRaw = parseInt(document.getElementById('logRetrolav').value);
  const durezaRaw   = parseFloat(document.getElementById('logDureza').value);
  const cyaRaw      = parseFloat(document.getElementById('logCya').value);
  return {
    fecha:      document.getElementById('logDate').value,
    hora:       document.getElementById('logTime').value,
    operador:   document.getElementById('logOperador').value,
    cloro:      parseFloat(document.getElementById('logCloro').value),
    clorocomb:  parseFloat(document.getElementById('logCloroComb').value),
    ph:         parseFloat(document.getElementById('logPh').value),
    alc:        parseFloat(document.getElementById('logAlc').value),
    cya:        isNaN(cyaRaw)      ? null : cyaRaw,
    turb:       parseFloat(document.getElementById('logTurb').value),
    temp:       parseFloat(document.getElementById('logTemp').value),
    dureza:     isNaN(durezaRaw)   ? null : durezaRaw,
    banistas:   isNaN(banistasRaw) ? null : banistasRaw,
    orp:        isNaN(orpRaw)      ? null : orpRaw,
    tds:        isNaN(tdsRaw)      ? null : tdsRaw,
    cond:       isNaN(condRaw)     ? null : condRaw,
    caudal:     isNaN(caudalRaw)   ? null : caudalRaw,
    horasFun:   isNaN(horasFunRaw) ? null : horasFunRaw,
    aguaRep:    isNaN(aguaRepRaw)  ? null : aguaRepRaw,
    retrolav:   isNaN(retrolavRaw) ? null : retrolavRaw,
    prodQuim:   document.getElementById('logProdQuim').value.trim(),
    averias:    document.getElementById('logAverias').value.trim(),
    notas:      document.getElementById('logNotas').value,
    fotoAgua:   _photos.fotoAgua   || null,
    fotoAveria: _photos.fotoAveria || null,
    ts:         editingLogTs || Date.now(),
  };
}

function _calcISLForEntry(entry) {
  if (!isFinite(entry.ph) || !isFinite(entry.temp) || !isFinite(entry.alc)) return;
  const hard = entry.dureza !== null ? entry.dureza : _lastDureza();
  const CT = _lsiInterp(_LSI_TEMP, entry.temp);
  const CD = _lsiInterp(_LSI_HARD, hard);
  const CA = _lsiInterp(_LSI_ALK,  entry.alc);
  entry.isl       = +(entry.ph + CT + CD + CA - 12.1).toFixed(2);
  entry.islStatus = entry.isl < -0.3 ? 'Corrosiva' : entry.isl > 0.5 ? 'Incrustante' : 'Equilibrada';
  entry.islDureza = hard;
}

function _rotateOldData() {
  const now = new Date();
  const sixAgo   = new Date(now); sixAgo.setMonth(sixAgo.getMonth() - 6);
  const threeAgo = new Date(now); threeAgo.setMonth(threeAgo.getMonth() - 3);
  const pad = n => String(n).padStart(2, '0');
  const toYMD = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  const sixCutoff   = toYMD(sixAgo);
  const threeCutoff = toYMD(threeAgo);

  let removedRecs  = 0;
  let strippedRecs = 0;

  const safeLoad = key => {
    try { return JSON.parse(localStorage.getItem(key) || '[]'); } catch { return []; }
  };
  const rotateList = (arr, photoKeys) => arr
    .filter(e => {
      if (!e.fecha || e.fecha < sixCutoff) { removedRecs++; return false; }
      return true;
    })
    .map(e => {
      if (e.fecha < threeCutoff && photoKeys.some(k => e[k])) {
        strippedRecs++;
        const patch = {};
        photoKeys.forEach(k => { patch[k] = null; });
        return { ...e, ...patch };
      }
      return e;
    });

  const bitacora = safeLoad('aqua_bitacora');
  if (Array.isArray(bitacora)) {
    _secSave('aqua_bitacora', JSON.stringify(rotateList(bitacora, ['fotoAgua', 'fotoAveria'])));
  }

  const afr = safeLoad('aqua_afr');
  if (Array.isArray(afr)) {
    _secSave('aqua_afr', JSON.stringify(rotateList(afr, ['foto'])));
  }

  const mnt = safeLoad('aqua_mantenimiento');
  if (Array.isArray(mnt)) {
    _secSave('aqua_mantenimiento', JSON.stringify(rotateList(mnt, ['foto'])));
  }

  renderLog();
  renderAFRIncidents();
  renderMnt();
  renderDashboardGauges();

  const parts = [];
  if (removedRecs  > 0) parts.push(`${removedRecs} registro${removedRecs > 1 ? 's' : ''} eliminado${removedRecs > 1 ? 's' : ''} (más de 6 meses)`);
  if (strippedRecs > 0) parts.push(`fotos de ${strippedRecs} registro${strippedRecs > 1 ? 's' : ''} eliminadas (3–6 meses, texto conservado)`);
  showToast(
    parts.length ? `Limpieza completada: ${parts.join('; ')}.` : 'No hay registros con más de 3 meses para limpiar.',
    parts.length ? 'success' : 'info',
    8000
  );
}

function _checkStorageUsage() {
  try {
    let bytes = 0;
    for (const k of Object.keys(localStorage)) bytes += localStorage[k].length * 2;
    if (bytes > 4_500_000) {
      showToast(
        `⚠️ Almacenamiento casi lleno (~${(bytes / 1e6).toFixed(1)} MB de ~5 MB). Elimina fotos o registros antiguos para evitar pérdida de datos.`,
        'error', 10000
      );
      if (!_rotationOffered) {
        _rotationOffered = true;
        setTimeout(() => showConfirm(
          `Almacenamiento al ~${Math.round(bytes / 50000)}%. ¿Limpiar automáticamente registros mayores a 6 meses y fotos mayores a 3 meses?`,
          _rotateOldData
        ), 1200);
      }
    } else if (bytes > 3_500_000) {
      showToast(
        `Almacenamiento local al ${Math.round(bytes / 50000)}%. Considera eliminar registros o fotos antiguas.`,
        'warning', 7000
      );
    }
  } catch (_) {}
}

function saveLog() {
  const entry = _buildLogEntry();
  _calcISLForEntry(entry);

  let log = getLog();
  let toastMsg;
  if (editingLogTs) {
    log = log.map(e => e.ts === editingLogTs ? entry : e);
    editingLogTs = null;
    document.getElementById('btnSaveLogText').textContent  = 'Guardar en bitácora';
    document.getElementById('logEditBanner').style.display = 'none';
    document.getElementById('btnCancelEdit').style.display = 'none';
    toastMsg = 'Registro actualizado correctamente.';
  } else {
    log.unshift(entry);
    _newLogTs = entry.ts;
    toastMsg = `Medición del ${entry.fecha} guardada en bitácora.`;
  }
  _secSave('aqua_bitacora', JSON.stringify(log));
  _checkStorageUsage();
  _logPage = 0;
  clearLogForm();
  renderLog();
  renderDashboardGauges();
  updateIRAPIBitacoraBtn();
  updateReportBtn();
  updateDashReportBtn();
  updateOperadorDatalist();
  showToast(toastMsg, 'success');
}

function deleteLog(ts) {
  showConfirm('¿Eliminar este registro? Esta acción no se puede deshacer.', () => {
    const log = getLog().filter(e => e.ts !== ts);
    _secSave('aqua_bitacora', JSON.stringify(log));
    if (!log.length) {
      sessionStorage.removeItem('aqua_irapi_result');
      sessionStorage.removeItem('aqua_irapi_sliders');
      _lsiClearResult();
      // Limpiar inputs LSI
      ['lsiPh','lsiTemp','lsiHard','lsiAlk'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
      });
    }
    renderLog();
    renderDashboardGauges();
    renderDashboardIndices();
    updateIRAPIBitacoraBtn();
    updateReportBtn();
    updateDashReportBtn();
    updateOperadorDatalist();
    showToast('Registro eliminado.', 'success');
  });
}

function renderLog() {
  let log     = getLog();
  const wrap  = document.getElementById('logTableWrap');
  const cnt   = document.getElementById('logCount');
  const total = log.length;

  // Banner "siguiente paso" — visible solo cuando hay al menos un registro
  const fnsBit = document.getElementById('fnsAfterBitacora');
  if (fnsBit) fnsBit.style.display = total > 0 ? 'flex' : 'none';

  // ── Filtros ────────────────────────────────────────────
  const desde     = document.getElementById('filterDesde')?.value     || '';
  const hasta     = document.getElementById('filterHasta')?.value     || '';
  const opQuery   = (document.getElementById('filterOperador')?.value || '').toLowerCase().trim();
  const soloFuera = document.getElementById('filterFueraRango')?.checked || false;

  const btnClear = document.getElementById('btnClearFilter');
  if (btnClear) btnClear.disabled = !desde && !hasta && !opQuery && !soloFuera;

  if (desde)     log = log.filter(e => e.fecha >= desde);
  if (hasta)     log = log.filter(e => e.fecha <= hasta);
  if (opQuery)   log = log.filter(e =>
    (e.operador || '').toLowerCase().includes(opQuery) ||
    (e.notas    || '').toLowerCase().includes(opQuery));
  if (soloFuera) log = log.filter(e =>
    PARAM_DEFS.some(p => { const v = e[p.key]; return v != null && (v < p.normMin || v > p.normMax); }));

  const totalFiltered = log.length;
  const totalPages    = Math.ceil(totalFiltered / LOG_PAGE_SIZE) || 1;
  if (_logPage >= totalPages) _logPage = totalPages - 1;
  const pageLog = log.slice(_logPage * LOG_PAGE_SIZE, (_logPage + 1) * LOG_PAGE_SIZE);

  if (cnt) cnt.textContent = totalFiltered < total
    ? `${totalFiltered} / ${total}${totalPages > 1 ? ` · p.${_logPage + 1}/${totalPages}` : ''}`
    : `${total}${totalPages > 1 ? ` · p.${_logPage + 1}/${totalPages}` : ''}`;

  if (!total) {
    wrap.innerHTML = '<p class="empty-state">Sin registros aún. Agregue la primera medición arriba.</p>';
    return;
  }
  if (!totalFiltered) {
    wrap.innerHTML = '<p class="empty-state">Sin registros que coincidan con el filtro.</p>';
    return;
  }

  const cc = (key, val) => {
    const p = PARAM_DEFS.find(d => d.key === key);
    return (p && val != null && (val < p.normMin || val > p.normMax)) ? ' class="cell-out-range"' : '';
  };

  wrap.innerHTML = `
    <div class="log-table-scroll">
    <table class="log-table">
      <thead>
        <tr>
          <th>Fecha</th><th>Hora</th><th>Operador</th>
          <th>Cl. Libre</th><th>Cl. Comb</th><th>pH</th><th>Alcalinidad</th><th>Dureza</th>
          <th>CYA</th><th>Turbiedad</th><th>Temp</th><th>ORP</th><th>TDS</th><th>Conduct.</th><th>ISL</th><th>Art.16</th><th>Bañistas</th><th></th>
        </tr>
      </thead>
      <tbody>
        ${pageLog.map(e => `
          <tr class="log-row-clickable" data-ts="${e.ts}" title="Ver detalle del registro">
            <td data-label="Fecha">${escapeHtml(e.fecha) || '–'}</td>
            <td data-label="Hora">${escapeHtml(fmt12h(e.hora))}</td>
            <td data-label="Operador">${escapeHtml(e.operador) || '–'}</td>
            <td data-label="Cl. Libre"${cc('cloro',     e.cloro    )}>${e.cloro     ?? '–'} ppm</td>
            <td data-label="Cl. Comb" ${cc('clorocomb', e.clorocomb)}>${e.clorocomb != null && !isNaN(e.clorocomb) ? e.clorocomb + ' ppm' : '–'}</td>
            <td data-label="pH"       ${cc('ph',         e.ph       )}>${e.ph        ?? '–'}</td>
            <td data-label="Alcalinidad"${cc('alc',   e.alc  )}>${e.alc   ?? '–'} ppm</td>
            <td data-label="Dureza"${cc('dureza', e.dureza)}>${e.dureza != null && !isNaN(e.dureza) ? e.dureza + ' ppm' : '–'}</td>
            <td data-label="CYA"${cc('cya',   e.cya  )}>${e.cya   ?? '–'} ppm</td>
            <td data-label="Turbiedad"${cc('turb',  e.turb )}>${e.turb  ?? '–'} UNT</td>
            <td data-label="Temp."${cc('temp',  e.temp )}>${e.temp  ?? '–'} °C</td>
            <td data-label="ORP"${e.orp != null && !isNaN(e.orp) ? (e.orp <= 700 ? ' class="cell-ok"' : ' class="cell-out"') : ''}>${e.orp != null && !isNaN(e.orp) ? e.orp + ' mV' : '–'}</td>
            <td data-label="TDS"${cc('tds', e.tds)}>${e.tds != null && !isNaN(e.tds) ? e.tds + ' mg/L' : '–'}</td>
            <td data-label="Conduct."${cc('cond', e.cond)}>${e.cond != null && !isNaN(e.cond) ? e.cond + ' µS/cm' : '–'}</td>
            <td data-label="ISL">${e.isl != null ? `<span style="font-weight:700;color:${e.islStatus==='Equilibrada'?'#0cb86a':e.islStatus==='Incrustante'?'#f59e0b':'#ef4444'}">${e.isl.toFixed(2)}</span>` : '–'}</td>
            <td data-label="Art.16" title="${[e.caudal != null ? 'Caudal: ' + e.caudal + ' m³/h' : '', e.horasFun != null ? 'Horas: ' + e.horasFun + 'h' : '', e.aguaRep != null ? 'Agua: ' + e.aguaRep + ' m³' : '', e.retrolav != null ? 'Retrolavados: ' + e.retrolav : '', e.prodQuim ? 'Prod: ' + escapeHtml(e.prodQuim) : '', e.averias ? 'Averías: ' + escapeHtml(e.averias) : ''].filter(Boolean).join(' · ') || 'Sin datos Art.16'}">${(e.caudal != null || e.horasFun != null || e.aguaRep != null || e.retrolav != null || e.prodQuim || e.averias) ? '✓' : '–'}</td>
            <td data-label="Bañistas">${e.banistas ?? '–'}</td>
            <td data-label="">
              <div class="log-row-actions">
                ${(e.fotoAgua || e.fotoAveria) ? `<button class="btn-cam-log" title="Ver foto adjunta" aria-label="Ver foto del registro"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg></button>` : ''}
                <button class="btn-edit-log" title="Editar registro" aria-label="Editar registro del ${e.fecha}">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                  </svg>
                </button>
                <button class="btn-delete-log" title="Eliminar registro" aria-label="Eliminar registro del ${e.fecha}">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
                    <path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/>
                  </svg>
                </button>
              </div>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    </div>
    ${totalPages > 1 ? `
    <div class="log-pagination">
      <button class="log-pg-btn" data-page="0" ${_logPage === 0 ? 'disabled' : ''} aria-label="Primera página">«</button>
      <button class="log-pg-btn" data-page="${_logPage - 1}" ${_logPage === 0 ? 'disabled' : ''} aria-label="Página anterior">‹</button>
      <span class="log-pg-info">${_logPage + 1} / ${totalPages}</span>
      <button class="log-pg-btn" data-page="${_logPage + 1}" ${_logPage >= totalPages - 1 ? 'disabled' : ''} aria-label="Página siguiente">›</button>
      <button class="log-pg-btn" data-page="${totalPages - 1}" ${_logPage >= totalPages - 1 ? 'disabled' : ''} aria-label="Última página">»</button>
    </div>` : ''}
  `;

  if (_newLogTs) {
    const newRow = wrap.querySelector(`tr[data-ts="${_newLogTs}"]`);
    if (newRow) newRow.classList.add('log-row-new');
    _newLogTs = 0;
  }
}

function viewLog(ts) {
  const entry = getLog().find(e => e.ts === ts);
  if (!entry) return;

  const overlay = document.getElementById('logDetailOverlay');
  const title   = document.getElementById('logDetailTitle');
  const meta    = document.getElementById('logDetailMeta');
  const body    = document.getElementById('logDetailBody');

  title.textContent = `Registro del ${entry.fecha || '–'}`;
  meta.textContent  = `${fmt12h(entry.hora, '')} · ${entry.operador || 'Sin operador'}`;

  const paramRows = [
    { key: 'cloro',     label: 'Cloro libre residual',  unit: 'ppm',   normMin: 2.0,  normMax: 4.0  },
    { key: 'clorocomb', label: 'Cloro combinado',        unit: 'ppm',   normMin: 0,    normMax: 0.3  },
    { key: 'ph',        label: 'pH',                     unit: '',      normMin: 6.8,  normMax: 7.3  },
    { key: 'alc',       label: 'Alcalinidad total',      unit: 'ppm',   normMin: 20,   normMax: 150  },
    { key: 'dureza',    label: 'Dureza cálcica',         unit: 'ppm',   normMin: 200,  normMax: 700  },
    { key: 'cya',       label: 'Estabilizador (CYA)',    unit: 'ppm',   normMin: 0,    normMax: 75   },
    { key: 'turb',      label: 'Transparencia',          unit: 'UNT',   normMin: 0,    normMax: 0.5  },
    { key: 'temp',      label: 'Temperatura',            unit: '°C',    normMin: 0,    normMax: 40   },
    { key: 'orp',       label: 'Oxidación (ORP)',        unit: 'mV',    normMin: 0,    normMax: 700, warnBelow: 650 },
    { key: 'tds',       label: 'Sólidos disueltos (TDS)',unit: 'mg/L',  normMin: 1000, normMax: 1200 },
    { key: 'cond',      label: 'Conductividad eléctrica',unit: 'µS/cm', normMin: 2000, normMax: 2400 },
  ];

  const paramHTML = paramRows.map(p => {
    const val = entry[p.key];
    if (val == null || isNaN(val)) return '';
    const inRange = val >= p.normMin && val <= p.normMax;
    const isWarn  = inRange && p.warnBelow !== undefined && val < p.warnBelow;
    const badge   = inRange
      ? (isWarn
        ? '<span class="log-detail-badge warn">⚠ Eficacia baja</span>'
        : '<span class="log-detail-badge ok">✓ En rango</span>')
      : '<span class="log-detail-badge out">✗ Fuera</span>';
    let devHTML = '';
    if (!inRange) {
      const raw     = val < p.normMin ? val - p.normMin : val - p.normMax;
      const sign    = raw > 0 ? '+' : '−';
      const abs     = parseFloat(Math.abs(raw).toFixed(2));
      const unitLbl = p.unit || 'unidades';
      devHTML = `<span class="log-detail-deviation">${sign}${abs} ${unitLbl} fuera del rango permitido (${p.normMin}–${p.normMax}${p.unit ? ' ' + p.unit : ''})</span>`;
    }
    return `<div class="log-detail-param ${inRange ? '' : 'param-out'}">
      <span class="log-detail-param-label">${p.label}</span>
      <span class="log-detail-param-val">${_safeNum(val)}${p.unit ? ' ' + p.unit : ''}</span>
      ${badge}${devHTML}
    </div>`;
  }).join('');

  const art16Items = [
    entry.caudal    != null ? `<li>Caudal: <strong>${_safeNum(entry.caudal)} m³/h</strong></li>` : '',
    entry.horasFun  != null ? `<li>Horas de funcionamiento: <strong>${_safeNum(entry.horasFun)} h</strong></li>` : '',
    entry.aguaRep   != null ? `<li>Agua repuesta: <strong>${_safeNum(entry.aguaRep)} m³</strong></li>` : '',
    entry.retrolav  != null ? `<li>Retrolavados: <strong>${_safeNum(entry.retrolav)}</strong></li>` : '',
    entry.prodQuim              ? `<li>Productos químicos: <strong>${escapeHtml(entry.prodQuim)}</strong></li>` : '',
    entry.averias               ? `<li>Averías / novedades: <strong>${escapeHtml(entry.averias)}</strong></li>` : '',
  ].filter(Boolean).join('');

  const art16HTML = art16Items
    ? `<div class="log-detail-section">
        <div class="log-detail-section-title">Art. 16 — Operación técnica</div>
        <ul class="log-detail-art16">${art16Items}</ul>
      </div>` : '';

  const extraHTML = (entry.banistas != null || entry.notas)
    ? `<div class="log-detail-section">
        <div class="log-detail-section-title">Información adicional</div>
        ${entry.banistas != null ? `<div class="log-detail-extra-row"><span>Bañistas</span><strong>${_safeNum(entry.banistas)}</strong></div>` : ''}
        ${entry.notas ? `<div class="log-detail-notas"><em>${escapeHtml(entry.notas)}</em></div>` : ''}
      </div>` : '';

  let islHTML = '';
  if (entry.isl != null) {
    const islColor  = entry.islStatus === 'Equilibrada' ? '#0cb86a' : entry.islStatus === 'Incrustante' ? '#f59e0b' : '#ef4444';
    const islBg     = entry.islStatus === 'Equilibrada' ? '#f0fdf4' : entry.islStatus === 'Incrustante' ? '#fffbeb' : '#fef2f2';
    const islBorder = entry.islStatus === 'Equilibrada' ? '#bbf7d0' : entry.islStatus === 'Incrustante' ? '#fde68a' : '#fecaca';
    const durezaNote = entry.dureza == null ? ` <span style="font-size:11px;color:#94a3b8">(dureza estimada: ${_safeNum(entry.islDureza)} ppm)</span>` : '';
    islHTML = `<div class="log-detail-section">
      <div class="log-detail-section-title">Índice de Saturación Langelier (ISL)</div>
      <div style="display:flex;align-items:center;gap:12px;padding:10px 14px;border-radius:8px;border:1px solid ${islBorder};background:${islBg}">
        <span style="font-family:'Space Grotesk',sans-serif;font-size:28px;font-weight:800;color:${islColor}">${_safeNum(entry.isl, 2)}</span>
        <div>
          <div style="font-weight:700;color:${islColor}">${entry.islStatus}</div>
          <div style="font-size:12px;color:#64748b">Rango óptimo: −0.3 a +0.5${durezaNote}</div>
        </div>
      </div>
    </div>`;
  }

  const fotosHTML = (entry.fotoAgua || entry.fotoAveria) ? `
    <div class="log-detail-section">
      <div class="log-detail-section-title">Evidencia fotográfica</div>
      <div class="log-detail-fotos">
        ${_safePhotoSrc(entry.fotoAgua)   ? `<div class="log-detail-foto-item"><span class="log-detail-foto-label">Estado del agua</span><img class="log-detail-foto-img" src="${_safePhotoSrc(entry.fotoAgua)}" alt="Foto del agua" /></div>` : ''}
        ${_safePhotoSrc(entry.fotoAveria) ? `<div class="log-detail-foto-item"><span class="log-detail-foto-label">Avería / equipo</span><img class="log-detail-foto-img" src="${_safePhotoSrc(entry.fotoAveria)}" alt="Foto avería" /></div>` : ''}
      </div>
    </div>` : '';

  body.innerHTML = `
    ${islHTML}
    <div class="log-detail-section">
      <div class="log-detail-section-title">Parámetros del agua</div>
      <div class="log-detail-params">${paramHTML || '<p class="log-detail-empty">Sin parámetros registrados.</p>'}</div>
    </div>
    ${art16HTML}
    ${extraHTML}
    ${fotosHTML}
    <div style="display:flex;gap:8px;margin-top:20px">
      <button class="btn btn-outline btn-danger-outline js-log-detail-delete" style="flex:1">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
        Eliminar
      </button>
      <button class="btn btn-outline js-log-detail-edit" style="flex:1">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        Editar
      </button>
    </div>
  `;

  body.querySelector('.js-log-detail-delete').addEventListener('click', () => { closeLogDetail(); deleteLog(entry.ts); });
  body.querySelector('.js-log-detail-edit').addEventListener('click',   () => { closeLogDetail(); editLog(entry.ts);   });

  overlay.style.display = 'flex';
  document.body.style.overflow = 'hidden';
}

function closeLogDetail(event) {
  if (event && event.target !== document.getElementById('logDetailOverlay')) return;
  const overlay = document.getElementById('logDetailOverlay');
  overlay.style.display = 'none';
  document.body.style.overflow = '';
}

function clearLogFilter() {
  ['filterDesde', 'filterHasta', 'filterOperador'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });
  const cb = document.getElementById('filterFueraRango');
  if (cb) cb.checked = false;
  _logPage = 0;
  renderLog();
  showToast('Filtros limpiados', 'success');
}

function goLogPage(page) {
  _logPage = page;
  renderLog();
  document.getElementById('logTableWrap')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── PROTOCOLO AFR ─────────────────────────────────────────
const AFR_STEPS = {
  solido: [
    { title: 'Evacuar la piscina', desc: 'Solicite a todos los bañistas salir del agua de inmediato. Restrinja el acceso.' },
    { title: 'Identificar el tipo de incidente', desc: 'Confirme que se trata de materia fecal sólida. Registre la hora del incidente.' },
    { title: 'Remover el residuo', desc: 'Use una red dedicada exclusivamente para esto. No utilice la red de limpieza normal.' },
    { title: 'Hipercloración', desc: 'Eleve el cloro residual a mínimo 10 ppm (rango recomendado: 8–12 ppm). Tiempo mínimo de contacto: 2 horas con pH entre 6.8 y 7.3. Si no puede descartarse Cryptosporidium, aplique 20 ppm durante 8.5 horas (CDC/MAHC).' },
    { title: 'Verificar pH', desc: 'Mantenga el pH entre 6.8 y 7.3 durante todo el proceso. El pH correcto garantiza eficacia del cloro.' },
    { title: 'Filtrar y registrar', desc: 'Active el sistema de filtración. Registre el incidente en la bitácora con hora y bañistas afectados.' },
    { title: 'Reapertura', desc: 'Valide que el cloro haya bajado al rango operativo (2–4 ppm), pH 6.8–7.3 y turbiedad ≤ 0.5 UNT antes de permitir el acceso.' },
  ],
  diarreico: [
    { title: 'Evacuar la piscina', desc: 'Solicite a todos los bañistas salir del agua de inmediato. Restrinja el acceso.' },
    { title: 'Identificar el tipo de incidente', desc: 'Confirme que se trata de materia fecal diarreica. Registre la hora exacta.' },
    { title: 'Notificar autoridad sanitaria', desc: 'Notifique de inmediato a la Secretaría de Salud local o autoridad sanitaria competente. La Res. 234/2026 y la Ley 1209/2008 exigen notificación obligatoria ante todo evento fecal diarreico. Registre la hora de notificación y el funcionario contactado.' },
    { title: 'Remover el residuo', desc: 'Use una red dedicada. Coloque el residuo en bolsa hermética y deseche.' },
    { title: 'Hipercloración', desc: 'Eleve el cloro residual a 20 ppm. Tiempo mínimo de contacto: 13 horas. Riesgo de Cryptosporidium.' },
    { title: 'Verificar pH', desc: 'Mantenga el pH entre 6.8 y 7.3. Monitoree cada 2 horas durante las 13 horas.' },
    { title: 'Filtrar y registrar', desc: 'Active el sistema de filtración continua. Registre el incidente con todos los detalles.' },
    { title: 'Reapertura', desc: 'Solo reabra tras verificar cloro ≥ 2 ppm, pH 6.8–7.3 y turbiedad ≤ 0.5 UNT.' },
  ],
  vomito: [
    { title: 'Evacuar la piscina', desc: 'Solicite a todos los bañistas salir del agua de inmediato. Restrinja el acceso.' },
    { title: 'Identificar el incidente', desc: 'Confirme la presencia de vómito. Registre la hora exacta y el área afectada.' },
    { title: 'Remover el residuo', desc: 'Retire el material visible con una red dedicada. Colóquelo en bolsa hermética y deseche.' },
    { title: 'Hipercloración', desc: 'Eleve el cloro residual a mínimo 2 ppm. Tiempo de contacto: 30 minutos a pH entre 6.8 y 7.3.' },
    { title: 'Verificar pH', desc: 'Mantenga el pH entre 6.8 y 7.3 durante todo el proceso. El rango correcto es esencial para la eficacia.' },
    { title: 'Filtrar y registrar', desc: 'Active filtración continua. Registre el incidente en la bitácora con operador a cargo y bañistas.' },
    { title: 'Reapertura', desc: 'Reabra solo tras verificar cloro ≥ 2 ppm, pH 6.8–7.3 y turbiedad ≤ 0.5 UNT.' },
  ],
};

function renderAFR() {
  const steps = AFR_STEPS[APP.afrType];
  const step  = steps[APP.afrStep];

  document.getElementById('afrStepLabel').textContent = `Paso ${APP.afrStep + 1} de ${steps.length}`;
  document.getElementById('afrTitle').textContent     = step.title;
  document.getElementById('afrDesc').textContent      = step.desc;

  document.getElementById('afrPrev').disabled = APP.afrStep === 0;

  const nextBtn = document.getElementById('afrNext');
  if (APP.afrStep === steps.length - 1) {
    nextBtn.textContent = 'Finalizar';
  } else {
    nextBtn.innerHTML = 'Siguiente <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>';
  }

  // Dots
  const dotsEl = document.getElementById('afrDots');
  dotsEl.innerHTML = steps.map((_, i) =>
    `<div class="afr-dot ${i === APP.afrStep ? 'active' : ''}"></div>`
  ).join('');

  renderAFRDoseBlock();
}

function _afrVol() {
  if (APP.volume > 0) return APP.volume;
  try {
    const v = parseFloat((JSON.parse(localStorage.getItem('aqua_reporte') || '{}')).repVolumen);
    if (!isNaN(v) && v > 0) return v;
  } catch {}
  return 0;
}

function renderAFRDoseBlock() {
  const block = document.getElementById('afrDoseBlock');
  if (!block) return;

  const HYPER_STEP = APP.afrType === 'diarreico' ? 4 : 3; // diarreico: +1 por paso "Notificar autoridad" en índice 2
  if (APP.afrStep !== HYPER_STEP) { block.hidden = true; return; }
  block.hidden = false;

  const TARGET = { solido: 10, diarreico: 20, vomito: 2 };
  const target = TARGET[APP.afrType] || 10;
  const vol    = _afrVol();

  const log       = getLog();
  const lastCloro = (log.length > 0 && log[0].cloro != null) ? +log[0].cloro : null;

  const cloroRow = lastCloro !== null
    ? `<div class="afr-dose-row"><span>Cloro actual (último registro)</span><strong>${_safeNum(lastCloro)} ppm</strong></div>` : '';

  const volRow = vol > 0
    ? `<div class="afr-dose-row"><span>Volumen de la piscina</span><strong>${vol.toFixed(1)} m³</strong></div>`
    : `<div class="afr-dose-row afr-dose-row-input">
         <span>Volumen de piscina</span>
         <div class="input-unit" style="max-width:120px">
           <input type="number" class="form-input" id="afrVolInput" min="1" max="9999" step="1"
                  placeholder="m³" />
           <span class="unit">m³</span>
         </div>
       </div>`;

  const escalate = APP.afrType === 'solido'
    ? `<div class="afr-dose-escalate">Si no puede descartarse Cryptosporidium: elevar a 20 ppm · 8.5 h</div>` : '';

  block.innerHTML = `
    <div class="afr-dose-title">Dosis de hipercloración — Cálculo automático</div>
    <div class="afr-dose-params">
      ${volRow}
      ${cloroRow}
      <div class="afr-dose-row afr-dose-target-row">
        <span>Cloro objetivo</span>
        <strong>${target} ppm</strong>
      </div>
    </div>
    <div id="afrDoseResult"></div>
    ${escalate}
    <div class="afr-dose-note">Disolver el producto en agua antes de agregar · Filtro encendido · Mantener pH 6.8–7.3</div>
  `;

  const afrVolEl = document.getElementById('afrVolInput');
  if (afrVolEl) afrVolEl.addEventListener('input', () => calcAFRDose());
  if (vol > 0) calcAFRDose(vol, target, lastCloro);
}

function calcAFRDose(volArg, targetArg, cloroArg) {
  const TARGET = { solido: 10, diarreico: 20, vomito: 2 };
  const target = targetArg !== undefined ? targetArg : TARGET[APP.afrType] || 10;

  let vol = volArg !== undefined ? volArg : 0;
  if (!vol) {
    const inp = document.getElementById('afrVolInput');
    vol = inp ? (parseFloat(inp.value) || 0) : 0;
  }
  if (!vol) vol = _afrVol();

  const resultEl = document.getElementById('afrDoseResult');
  if (!resultEl) return;
  if (vol <= 0) { resultEl.innerHTML = ''; return; }

  const log       = getLog();
  const lastCloro = cloroArg !== undefined ? cloroArg
                  : (log.length > 0 && log[0].cloro != null) ? +log[0].cloro : null;
  const delta     = lastCloro !== null ? Math.max(0, target - lastCloro) : target;

  if (delta <= 0) {
    resultEl.innerHTML = `<div class="afr-dose-ok">El cloro actual (${_safeNum(lastCloro)} ppm) ya alcanza el objetivo de ${_safeNum(target)} ppm — verificar con kit antes de continuar.</div>`;
    return;
  }

  const caclo = Math.round(delta * vol * 1.43);
  const naclo = Math.round(delta * vol * 5.78);

  const deltaRow = (lastCloro !== null)
    ? `<div class="afr-dose-row" style="margin-bottom:4px"><span>Diferencia a agregar</span><strong>${delta.toFixed(1)} ppm</strong></div>` : '';

  resultEl.innerHTML = `
    ${deltaRow}
    <div class="afr-dose-products">
      <div class="afr-dose-product">
        <span class="afr-dose-prod-name">Hipoclorito de calcio 70%</span>
        <span class="afr-dose-prod-qty">${caclo.toLocaleString('es-CO')} g</span>
        <span class="afr-dose-prod-form">${vol.toFixed(1)} m³ × ${delta.toFixed(1)} ppm × 1.43 g/m³·ppm</span>
      </div>
      <div class="afr-dose-product">
        <span class="afr-dose-prod-name">Hipoclorito de sodio 15%</span>
        <span class="afr-dose-prod-qty">${naclo.toLocaleString('es-CO')} ml</span>
        <span class="afr-dose-prod-form">${vol.toFixed(1)} m³ × ${delta.toFixed(1)} ppm × 5.78 ml/m³·ppm</span>
      </div>
    </div>
  `;
}

function afrStep(dir) {
  const content = document.getElementById('afrContent');
  if (!content || content.classList.contains('afr-anim-out-left') || content.classList.contains('afr-anim-out-right')) return;
  const steps  = AFR_STEPS[APP.afrType];
  const outCls = dir > 0 ? 'afr-anim-out-left'  : 'afr-anim-out-right';
  const inCls  = dir > 0 ? 'afr-anim-in-right'  : 'afr-anim-in-left';
  content.classList.add(outCls);
  setTimeout(() => {
    APP.afrStep = Math.max(0, Math.min(steps.length - 1, APP.afrStep + dir));
    content.classList.remove(outCls, 'afr-anim-in-right', 'afr-anim-in-left');
    renderAFR();
    void content.offsetWidth;
    content.classList.add(inCls);
  }, 150);
}

function setAFRType(type) {
  APP.afrType = type;
  APP.afrStep = 0;
  document.getElementById('btnSolido').classList.toggle('active',    type === 'solido');
  document.getElementById('btnDiarreico').classList.toggle('active', type === 'diarreico');
  document.getElementById('btnVomito').classList.toggle('active',    type === 'vomito');
  renderAFR();
}

function resetAFR() {
  const doReset = () => {
    APP.afrStep = 0;
    const opEl = document.getElementById('afrOperador');
    if (opEl) opEl.value = '';
    renderAFR();
  };
  if (APP.afrStep > 0) {
    showConfirm(
      `Estás en el Paso ${APP.afrStep + 1} del protocolo.\n\n¿Seguro que deseas reiniciar? Se perderá el progreso actual y el incidente NO quedará registrado.`,
      doReset
    );
  } else {
    doReset();
  }
}

function finishAFR() {
  const operador = document.getElementById('afrOperador').value || 'Sin nombre';
  const incidents = JSON.parse(localStorage.getItem('aqua_afr') || '[]');
  const now = new Date();
  incidents.unshift({
    tipo:     APP.afrType,
    operador,
    fecha:    localDateStr(now),
    hora:     now.toTimeString().slice(0, 5),
    ts:       Date.now(),
    foto:     _photos.afrFoto || null,
  });
  _secSave('aqua_afr', JSON.stringify(incidents));
  _applyPhoto('afrFoto', null);
  renderAFRIncidents();
  APP.afrStep = 0;
  renderAFR();
  showToast('Incidente AFR registrado correctamente.', 'success');
}

function _afrFechaDisplay(i) {
  const opts = { day: '2-digit', month: '2-digit', year: 'numeric' };
  if (i.fecha) {
    const d = new Date(i.fecha + 'T00:00:00');
    if (!isNaN(d)) return d.toLocaleDateString('es-CO', opts);
  }
  if (i.ts) return new Date(i.ts).toLocaleDateString('es-CO', opts);
  return '–';
}

function _updateAFRBanner(incidents) {
  const hasDiar = incidents.some(i => i.tipo === 'diarreico');
  const banner  = document.getElementById('afrEmergencyBanner');
  const card    = document.querySelector('.afr-card');
  if (banner) banner.style.display = hasDiar ? 'flex' : 'none';
  if (card)   card.classList.toggle('afr-emergency', hasDiar);
}

function renderAFRIncidents() {
  if (!_requireUnlocked()) return;
  const raw = (() => { try { return JSON.parse(localStorage.getItem('aqua_afr') || '[]'); } catch { return []; } })();
  const incidents = Array.isArray(raw) ? raw.filter(_isValidAFREntry) : [];
  const el = document.getElementById('afrIncidents');
  _updateAFRBanner(incidents);
  if (!incidents.length) {
    el.innerHTML = '<p class="empty-state">Sin incidentes registrados.</p>';
    return;
  }
  el.innerHTML = incidents.map(i => {
    const isDiar = i.tipo === 'diarreico';
    const isVom  = i.tipo === 'vomito';
    const incClass   = isDiar ? 'afr-inc-diarreico' : isVom ? 'afr-inc-vomito' : 'afr-inc-solido';
    const badgeClass = isDiar ? 'afr-inc-badge-emergencia' : isVom ? 'afr-inc-badge-vomito' : 'afr-inc-badge-solido';
    const badgeText  = isDiar ? 'EMERGENCIA' : isVom ? 'Vómito' : 'Sólido';
    const iconColor  = isDiar ? '#dc2626' : isVom ? '#d97706' : 'var(--warning)';
    return `
    <div class="afr-incident-item ${incClass}" data-ts="${i.ts}" title="Ver detalle del incidente">
      <div class="afr-incident-info">
        <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="2" style="flex-shrink:0"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <div>
          <strong>${escapeHtml(_afrFechaDisplay(i))} · ${escapeHtml(fmt12h(i.hora, ''))}</strong>
          <span class="afr-inc-badge ${badgeClass}">${badgeText}</span><br>
          <span style="font-size:13px;color:var(--text-muted)">Operador: ${escapeHtml(i.operador) || '–'}</span>
        </div>
      </div>
      <div class="afr-incident-actions">
        <button class="btn-edit-log" title="Editar incidente" aria-label="Editar incidente">
          <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </button>
        <button class="btn-delete-log" title="Eliminar incidente" aria-label="Eliminar incidente">
          <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
        </button>
      </div>
    </div>`;
  }).join('');
}

function deleteAFRIncident(ts) {
  if (!_requireUnlocked()) return;
  showConfirm('¿Eliminar este incidente? Esta acción no se puede deshacer.', () => {
    const incidents = JSON.parse(localStorage.getItem('aqua_afr') || '[]').filter(i => i.ts !== ts);
    _secSave('aqua_afr', JSON.stringify(incidents));
    renderAFRIncidents();
    showToast('Incidente eliminado.', 'success');
  });
}

function editAFRIncident(ts) {
  if (!_requireUnlocked()) return;
  const incidents = JSON.parse(localStorage.getItem('aqua_afr') || '[]');
  const i = incidents.find(x => x.ts === ts);
  if (!i) return;
  _afrEditTs = ts;
  document.getElementById('afrEditTipo').value            = i.tipo            || 'solido';
  document.getElementById('afrEditFecha').value           = i.fecha           || '';
  document.getElementById('afrEditHora').value            = i.hora            || '';
  document.getElementById('afrEditOperador').value        = i.operador        || '';
  document.getElementById('afrEditCloroFinal').value      = i.cloroFinal      ?? '';
  document.getElementById('afrEditPhFinal').value         = i.phFinal         ?? '';
  document.getElementById('afrEditTurbFinal').value       = i.turbFinal       ?? '';
  document.getElementById('afrEditFechaReapertura').value = i.fechaReapertura || '';
  document.getElementById('afrEditHoraReapertura').value  = i.horaReapertura  || '';
  document.getElementById('afrEditOverlay').style.display = 'flex';
}

function closeAFREdit(e) {
  if (e && e.target !== document.getElementById('afrEditOverlay')) return;
  document.getElementById('afrEditOverlay').style.display = 'none';
  _afrEditTs = null;
}

function viewAFRIncident(ts) {
  if (!_requireUnlocked()) return;
  const incidents = JSON.parse(localStorage.getItem('aqua_afr') || '[]');
  const i = incidents.find(x => x.ts === ts);
  if (!i) return;

  const isDiar = i.tipo === 'diarreico';
  const isVom  = i.tipo === 'vomito';
  const tipoLabel  = isDiar ? 'Diarreico' : isVom ? 'Vómito' : 'Sólido';
  const badgeClass = isDiar ? 'afr-inc-badge-emergencia' : isVom ? 'afr-inc-badge-vomito' : 'afr-inc-badge-solido';
  const badgeText  = isDiar ? 'EMERGENCIA' : isVom ? 'Vómito' : 'Sólido';
  const protDesc   = isDiar
    ? 'Hipercloración a 20 ppm · Cierre mínimo 13 horas · Riesgo de Cryptosporidium. Se requiere notificación a autoridad sanitaria.'
    : isVom
    ? 'Ajuste de cloro libre a 2 ppm · Inspección y limpieza inmediata del área afectada.'
    : 'Extracción física del material · Sin cierre obligatorio · Verificar niveles de cloro residual.';

  document.getElementById('afrDetailTitle').innerHTML =
    `Incidente AFR <span class="afr-inc-badge ${badgeClass}" style="font-size:11px">${badgeText}</span>`;
  document.getElementById('afrDetailMeta').textContent =
    `${i.fecha || '–'} · ${fmt12h(i.hora, '')} · ${i.operador || 'Sin operador'}`;

  const hasCierre = i.fechaReapertura || i.cloroFinal != null || i.phFinal != null || i.turbFinal != null;
  const cierreSection = hasCierre
    ? `<div class="log-detail-section">
        <div class="log-detail-section-title" style="color:#0cb86a">✓ Cierre del protocolo</div>
        ${i.cloroFinal != null ? `<div class="log-detail-param"><span class="log-detail-param-label">Cloro libre post-tratamiento</span><span class="log-detail-param-val">${i.cloroFinal} ppm ${i.cloroFinal >= 2 && i.cloroFinal <= 4 ? '<span class="log-detail-badge ok">✓ En rango</span>' : '<span class="log-detail-badge out">✗ Fuera</span>'}</span></div>` : ''}
        ${i.phFinal    != null ? `<div class="log-detail-param"><span class="log-detail-param-label">pH post-tratamiento</span><span class="log-detail-param-val">${i.phFinal} ${i.phFinal >= 6.8 && i.phFinal <= 7.3 ? '<span class="log-detail-badge ok">✓ En rango</span>' : '<span class="log-detail-badge out">✗ Fuera</span>'}</span></div>` : ''}
        ${i.turbFinal  != null ? `<div class="log-detail-param"><span class="log-detail-param-label">Turbiedad post-tratamiento</span><span class="log-detail-param-val">${i.turbFinal} UNT ${i.turbFinal <= 0.5 ? '<span class="log-detail-badge ok">✓ ≤ 0.5</span>' : '<span class="log-detail-badge out">✗ > 0.5</span>'}</span></div>` : ''}
        ${i.fechaReapertura ? `<div class="log-detail-param"><span class="log-detail-param-label">Reapertura</span><span class="log-detail-param-val">${i.fechaReapertura}${i.horaReapertura ? ' · ' + fmt12h(i.horaReapertura) : ''}</span></div>` : ''}
      </div>`
    : `<div class="log-detail-section">
        <div style="display:flex;align-items:center;gap:8px;padding:10px 12px;background:#fef3c7;border:1px solid #fde68a;border-radius:8px;font-size:12px;color:#92400e">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          Cierre pendiente — registra cloro final, pH, turbiedad y fecha de reapertura al editar este incidente.
        </div>
      </div>`;

  document.getElementById('afrDetailBody').innerHTML = `
    <div class="log-detail-section">
      <div class="log-detail-section-title">Información del incidente</div>
      <div class="log-detail-param">
        <span class="log-detail-param-label">Tipo de incidente</span>
        <span class="log-detail-param-val">${tipoLabel}</span>
      </div>
      <div class="log-detail-param">
        <span class="log-detail-param-label">Fecha</span>
        <span class="log-detail-param-val">${escapeHtml(i.fecha) || '–'}</span>
      </div>
      <div class="log-detail-param">
        <span class="log-detail-param-label">Hora</span>
        <span class="log-detail-param-val">${escapeHtml(fmt12h(i.hora))}</span>
      </div>
      <div class="log-detail-param">
        <span class="log-detail-param-label">Operador a cargo</span>
        <span class="log-detail-param-val">${escapeHtml(i.operador) || '–'}</span>
      </div>
    </div>
    <div class="log-detail-section">
      <div class="log-detail-section-title">Protocolo aplicado (Res. 234/2026)</div>
      <p style="font-size:13px;color:var(--text-muted);line-height:1.6;margin:0">${protDesc}</p>
    </div>
    ${cierreSection}
    ${i.foto ? `<div class="log-detail-section">
      <div class="log-detail-section-title">Evidencia fotográfica</div>
      <div class="log-detail-fotos">
        <div class="log-detail-foto-item"><span class="log-detail-foto-label">Foto del incidente</span><img class="log-detail-foto-img" src="${_safePhotoSrc(i.foto)}" alt="Foto del incidente AFR" /></div>
      </div>
    </div>` : ''}
    <div style="display:flex;gap:8px;margin-top:20px">
      <button class="btn btn-outline js-afr-detail-edit" style="flex:1">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        Editar
      </button>
      <button class="btn btn-primary js-afr-detail-close" style="flex:1">Cerrar</button>
    </div>
  `;

  const afrBody = document.getElementById('afrDetailBody');
  afrBody.querySelector('.js-afr-detail-edit').addEventListener('click',  () => { closeAFRDetail(); editAFRIncident(i.ts); });
  afrBody.querySelector('.js-afr-detail-close').addEventListener('click', () =>   closeAFRDetail());

  document.getElementById('afrDetailOverlay').style.display = 'flex';
}

function closeAFRDetail(e) {
  if (e && e.target !== document.getElementById('afrDetailOverlay')) return;
  document.getElementById('afrDetailOverlay').style.display = 'none';
}

function saveAFREdit() {
  if (!_requireUnlocked()) return;
  if (!_afrEditTs) return;
  const cloroFinalRaw = parseFloat(document.getElementById('afrEditCloroFinal').value);
  const phFinalRaw    = parseFloat(document.getElementById('afrEditPhFinal').value);
  const turbFinalRaw  = parseFloat(document.getElementById('afrEditTurbFinal').value);
  let incidents = JSON.parse(localStorage.getItem('aqua_afr') || '[]');
  incidents = incidents.map(i => i.ts !== _afrEditTs ? i : {
    ...i,
    tipo:             document.getElementById('afrEditTipo').value,
    fecha:            document.getElementById('afrEditFecha').value,
    hora:             document.getElementById('afrEditHora').value,
    operador:         document.getElementById('afrEditOperador').value,
    cloroFinal:       isNaN(cloroFinalRaw) ? null : cloroFinalRaw,
    phFinal:          isNaN(phFinalRaw)    ? null : phFinalRaw,
    turbFinal:        isNaN(turbFinalRaw)  ? null : turbFinalRaw,
    fechaReapertura:  document.getElementById('afrEditFechaReapertura').value || null,
    horaReapertura:   document.getElementById('afrEditHoraReapertura').value  || null,
  });
  _secSave('aqua_afr', JSON.stringify(incidents));
  document.getElementById('afrEditOverlay').style.display = 'none';
  _afrEditTs = null;
  renderAFRIncidents();
  showToast('Incidente actualizado.', 'success');
}

// ── REPORTE MENSUAL ───────────────────────────────────────
function saveReportFields() {
  const data = {
    repNombre:      document.getElementById('repNombre').value,
    repResponsable: document.getElementById('repResponsable').value,
    repUbicacion:   document.getElementById('repUbicacion').value,
    repVolumen:     document.getElementById('repVolumen').value,
  };
  localStorage.setItem('aqua_reporte', JSON.stringify(data));
}

function restoreReportFields() {
  try {
    const data = JSON.parse(localStorage.getItem('aqua_reporte')) || {};
    // Eliminar valores que coincidan con los antiguos defaults hardcodeados
    const OLD_VOLS = ['48', '48.0', '60'];
    if (data.repNombre === 'Piscina Principal')  delete data.repNombre;
    if (data.repUbicacion === 'Bogotá, Colombia') delete data.repUbicacion;
    if (OLD_VOLS.includes(String(data.repVolumen))) delete data.repVolumen;

    if (data.repNombre)      document.getElementById('repNombre').value      = data.repNombre;
    if (data.repResponsable) document.getElementById('repResponsable').value = data.repResponsable;
    if (data.repUbicacion)   document.getElementById('repUbicacion').value   = data.repUbicacion;
    if (data.repVolumen)     document.getElementById('repVolumen').value      = data.repVolumen;

    localStorage.setItem('aqua_reporte', JSON.stringify(data));
  } catch {}
}

function getReportLog() {
  const desde = document.getElementById('repDesde')?.value || '';
  const hasta  = document.getElementById('repHasta')?.value  || '';
  let log = getLog();
  if (desde) log = log.filter(e => e.fecha >= desde);
  if (hasta)  log = log.filter(e => e.fecha <= hasta);
  return log;
}

function onRepRangeChange() {
  const desde = document.getElementById('repDesde')?.value || '';
  const hasta  = document.getElementById('repHasta')?.value  || '';
  const btn   = document.getElementById('btnClearRepRange');
  if (btn) btn.disabled = !desde && !hasta;
  updateReportSummary();
  updateReportBtn();
}

function clearRepRange() {
  const d = document.getElementById('repDesde');
  const h = document.getElementById('repHasta');
  if (d) d.value = '';
  if (h) h.value = '';
  onRepRangeChange();
}

function updateReportSummary() {
  const log = getReportLog();

  const titleEl = document.getElementById('repSummaryTitle');
  if (titleEl) {
    if (log.length) {
      const logDesde = log[log.length - 1].fecha || '';
      const logHasta = log[0].fecha || '';
      titleEl.textContent = logDesde === logHasta
        ? `Resumen · ${logDesde}`
        : `Resumen · ${logDesde} al ${logHasta}`;
    } else {
      titleEl.textContent = 'Resumen · sin registros en el rango';
    }
  }

  const desde = log.length ? log[log.length - 1].fecha : null;
  const hasta  = log.length ? log[0].fecha : null;
  const allAfr = (() => { try { return JSON.parse(localStorage.getItem('aqua_afr') || '[]'); } catch { return []; } })().filter(_isValidAFREntry);
  const incidents = desde && hasta
    ? allAfr.filter(i => { const f = i.fecha || ''; return f >= desde && f <= hasta; })
    : [];

  document.getElementById('repMediciones').textContent = log.length;
  document.getElementById('repIncidentes').textContent = incidents.length;

  const pctIds = ['repCloro','repPh','repAlc','repCya','repTurb','repTemp'];

  if (!log.length) {
    pctIds.forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '–'; });
    ['repCloroComb','repOrp','repTds','repCond','repDureza'].forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '–'; });
    return;
  }

  const pct = (ok) => ((log.filter(ok).length / log.length) * 100).toFixed(0) + '%';
  const pctOpt = (filter, ok) => { const sub = log.filter(filter); return sub.length ? ((sub.filter(ok).length / sub.length) * 100).toFixed(0) + '%' : '–'; };

  document.getElementById('repCloro').textContent = pct(e => e.cloro >= 2.0 && e.cloro <= 4.0);
  const ccLogs = log.filter(e => e.clorocomb != null && !isNaN(e.clorocomb));
  document.getElementById('repCloroComb').textContent = ccLogs.length
    ? ((ccLogs.filter(e => e.clorocomb <= 0.3).length / ccLogs.length) * 100).toFixed(0) + '%'
    : '–';
  document.getElementById('repOrp').textContent  = pctOpt(e => e.orp  != null && !isNaN(e.orp),  e => e.orp  <= 700);
  document.getElementById('repTds').textContent  = pctOpt(e => e.tds  != null && !isNaN(e.tds),  e => e.tds  >= 1000 && e.tds  <= 1200);
  document.getElementById('repCond').textContent = pctOpt(e => e.cond != null && !isNaN(e.cond), e => e.cond >= 2000 && e.cond <= 2400);
  document.getElementById('repPh').textContent    = pct(e => e.ph   >= 6.8 && e.ph   <= 7.3);
  document.getElementById('repAlc').textContent   = pct(e => e.alc  >= 20  && e.alc  <= 150);
  document.getElementById('repCya').textContent   = pctOpt(e => e.cya != null && !isNaN(e.cya), e => e.cya >= 0 && e.cya <= 75);
  document.getElementById('repTurb').textContent  = pct(e => e.turb >= 0   && e.turb <= 0.5);
  document.getElementById('repTemp').textContent  = pctOpt(e => e.temp != null && !isNaN(e.temp), e => e.temp <= 40);
  document.getElementById('repDureza').textContent = pctOpt(e => e.dureza != null && !isNaN(e.dureza), e => e.dureza >= 200 && e.dureza <= 700);
}

function updateDashReportBtn() {
  const btn = document.getElementById('btnDashReport');
  if (!btn) return;
  const ready = getLog().length >= 1;
  btn.classList.toggle('btn-locked', !ready);
  btn.setAttribute('aria-disabled', String(!ready));
}

function dashboardReportClick() {
  if (getLog().length < 1) {
    showToast('Sin registros en la bitácora. Agrega mediciones para generar el reporte.', 'info');
    return;
  }
  navigate('reporte');
}

function updateReportBtn() {
  const btn  = document.getElementById('btnGeneratePDF');
  const note = document.getElementById('repPdfNote');
  if (!btn) return;
  const log   = getReportLog();
  const count = log.length;
  const ready = count >= 1;
  const desde = document.getElementById('repDesde')?.value || '';
  const hasta  = document.getElementById('repHasta')?.value  || '';
  const hasFilter = desde || hasta;
  btn.disabled = !ready;
  if (note) {
    if (!ready) {
      note.textContent = hasFilter
        ? 'Sin registros en el rango seleccionado.'
        : 'Sin registros en la bitácora.';
    } else {
      note.textContent = hasFilter
        ? `${count} registro${count !== 1 ? 's' : ''} en el rango seleccionado`
        : `${count} registro${count !== 1 ? 's' : ''} disponibles`;
    }
  }
}

function generatePDF() {
  const btn = document.getElementById('btnGeneratePDF');

  if (window.jspdf?.jsPDF) {
    _doPDF();
    return;
  }

  if (btn) { btn.disabled = true; btn.dataset.orig = btn.innerHTML; btn.innerHTML = '⏳ Cargando…'; }

  const restore = () => {
    if (btn && btn.dataset.orig) { btn.disabled = false; btn.innerHTML = btn.dataset.orig; delete btn.dataset.orig; }
  };
  const onError = () => {
    restore();
    showToast('Error al cargar el generador de PDF. Verifica tu conexión.', 'error');
  };
  const loadScript = (src, integrity, cb) => {
    const s = document.createElement('script');
    s.src = src;
    s.integrity = integrity;
    s.crossOrigin = 'anonymous';
    s.onload = cb;
    s.onerror = onError;
    document.head.appendChild(s);
  };

  loadScript(
    'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js',
    'sha512-qZvrmS2ekKPF2mSznTQsxqPgnpkI4DNTlrdUmTzrDgektczlKNRRhy5X5AAOnx5S09ydFYWWNSfcEqDTTHgtNA==',
    () => loadScript(
      'https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.8.2/jspdf.plugin.autotable.min.js',
      'sha512-2/YdOMV+YNpanLCF5MdQwaoFRVbTmrJ4u4EpqS/USXAQNUDgI5uwYi6J98WVtJKcfe1AbgerygzDFToxAlOGEQ==',
      () => { restore(); _doPDF(); }
    )
  );
}

function _loadImgB64(src) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      const c = document.createElement('canvas');
      c.width = img.naturalWidth; c.height = img.naturalHeight;
      c.getContext('2d').drawImage(img, 0, 0);
      resolve(c.toDataURL('image/png'));
    };
    img.onerror = reject;
    img.src = src;
  });
}

async function _sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function _pdfIntegrityCheck() {
  const checks = [];
  for (const key of ['aqua_bitacora', 'aqua_afr']) {
    const json = localStorage.getItem(key);
    const sig  = localStorage.getItem(key + '_sig');
    if (!json || !sig) { checks.push({ key, status: 'unsigned' }); continue; }
    try {
      const ok = await _INTEGRITY.verify(json, sig);
      checks.push({ key, status: ok ? 'ok' : 'tampered' });
    } catch { checks.push({ key, status: 'error' }); }
  }
  const tampered = checks.filter(c => c.status === 'tampered');
  return { clean: tampered.length === 0, tampered };
}

async function _doPDF() {
  const btn = document.getElementById('btnGeneratePDF');
  if (btn) { btn.disabled = true; btn.dataset.orig = btn.dataset.orig || btn.innerHTML; btn.innerHTML = '⏳ Generando PDF…'; }
  try {
    const integrity = await _pdfIntegrityCheck();
    if (!integrity.clean) {
      const keys = integrity.tampered.map(c => c.key).join(', ');
      showToast(`Advertencia de integridad: los datos de ${keys} pueden haber sido modificados externamente. El PDF incluirá una advertencia.`, 'warning', 7000);
    }
    const [logoB64, logHash] = await Promise.all([
      _loadImgB64('Multimedia/logo1.png').catch(() => null),
      _sha256Hex(localStorage.getItem('aqua_bitacora') || '[]'),
    ]);
    await __buildPDF(logoB64, integrity, logHash);
  } catch (err) {
    showToast('Error al generar el PDF. Intenta de nuevo.', 'error');
  } finally {
    if (btn && btn.dataset.orig) { btn.disabled = false; btn.innerHTML = btn.dataset.orig; delete btn.dataset.orig; }
  }
}

async function __buildPDF(logoB64, integrity, logHash) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  const nombre      = document.getElementById('repNombre').value      || 'Sin nombre';
  const responsable = document.getElementById('repResponsable').value  || '–';
  const ubicacion   = document.getElementById('repUbicacion').value   || '–';
  const volumen     = document.getElementById('repVolumen').value      || '–';
  const log    = getReportLog();
  const desde  = log.length ? log[log.length - 1].fecha : null;
  const hasta  = log.length ? log[0].fecha : null;
  const allAfr = (() => { try { return JSON.parse(localStorage.getItem('aqua_afr') || '[]'); } catch { return []; } })().filter(_isValidAFREntry);
  const incidents = desde && hasta
    ? allAfr.filter(i => { const f = i.fecha || ''; return f >= desde && f <= hasta; })
    : [];
  const periodo = desde && hasta && desde !== hasta ? `${desde} al ${hasta}` : (desde || '–');
  const pct = (arr, ok) => arr.length ? ((arr.filter(ok).length / arr.length) * 100).toFixed(0) + '%' : '–';

  const genTs    = new Date();
  const genLocal = genTs.toLocaleString('es-CO', { dateStyle: 'long', timeStyle: 'medium' });
  const hashShort = logHash ? logHash.slice(0, 16) + '…' + logHash.slice(-8) : '–';

  // ── Metadata del documento ────────────────────────────────
  doc.setProperties({
    title:    `Reporte Calidad del Agua — ${nombre}`,
    subject:  `Período: ${periodo}`,
    author:   responsable,
    creator:  'Brazada Aqua Tech · PWA · Res. 234/2026',
    keywords: 'piscina, calidad agua, resolución 234, Colombia',
  });

  // ── Membrete ─────────────────────────────────────────────
  // Área blanca superior
  doc.setFillColor(255, 255, 255);
  doc.rect(0, 0, 210, 28, 'F');

  // Logo
  if (logoB64) {
    doc.addImage(logoB64, 'PNG', 10, 2, 15, 21);
  }

  // Nombre y subtítulo
  doc.setTextColor(30, 41, 59);
  doc.setFontSize(15);
  doc.setFont('helvetica', 'bold');
  doc.text('Brazada Aqua Tech', 29, 11);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100, 116, 139);
  doc.text('Sistema de Gestión de Piscinas · Resolución 234 / 2026 · Colombia', 29, 18);
  doc.text(`Generado: ${genLocal}`, 196, 11, { align: 'right' });

  // Banda oscura
  doc.setFillColor(30, 41, 59);
  doc.rect(0, 28, 210, 9, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text('Reporte Mensual de Calidad del Agua', 105, 34, { align: 'center' });

  // ── Datos del establecimiento ────────────────────────────
  doc.setTextColor(30, 41, 59);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.text('Datos del establecimiento', 14, 47);

  doc.autoTable({
    startY: 51,
    body: [
      ['Nombre de la piscina', nombre,     'Responsable', responsable],
      ['Ubicación',            ubicacion,  'Volumen base', volumen + ' m³'],
      ['Período',              periodo,     '',             ''],
    ],
    theme: 'plain',
    styles:      { fontSize: 9, cellPadding: 2 },
    columnStyles: {
      0: { fontStyle: 'bold', cellWidth: 42, textColor: [100, 116, 139] },
      1: { cellWidth: 55 },
      2: { fontStyle: 'bold', cellWidth: 42, textColor: [100, 116, 139] },
      3: { cellWidth: 55 },
    },
    margin: { left: 14, right: 14 },
  });

  // ── helpers estadísticos ─────────────────────────────────
  const _vals = (field) => log.map(e => e[field]).filter(v => v != null && v !== '' && isFinite(+v)).map(Number);
  const _avg  = (field) => { const v = _vals(field); return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null; };
  const _min  = (field) => { const v = _vals(field); return v.length ? Math.min(...v) : null; };
  const _max  = (field) => { const v = _vals(field); return v.length ? Math.max(...v) : null; };
  const _pct  = (ok)    => { const n = log.filter(ok).length; return log.length ? Math.round((n / log.length) * 100) : null; };
  const _fmt  = (v, d)  => v != null ? v.toFixed(d) : '–';

  // ── Resumen del periodo ──────────────────────────────────
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 41, 59);
  doc.text('Resumen del periodo', 14, doc.lastAutoTable.finalY + 12);

  const paramRows = [
    { label: 'Cloro libre residual', unit: 'ppm', field: 'cloro',     dec: 1, ok: e => e.cloro >= 2.0 && e.cloro <= 4.0,                                                    range: '2.0 – 4.0 ppm' },
    { label: 'Cloro combinado',      unit: 'ppm', field: 'clorocomb', dec: 2, ok: e => { const v = +e.clorocomb; return isNaN(v) ? true : v >= 0 && v <= 0.3; },             range: '0 – 0.3 ppm'   },
    { label: 'pH',                   unit: '',    field: 'ph',        dec: 2, ok: e => e.ph   >= 6.8 && e.ph   <= 7.3,                                                    range: '6.8 – 7.3'     },
    { label: 'Alcalinidad total',     unit: 'ppm', field: 'alc',    dec: 0, ok: e => e.alc    >= 20  && e.alc    <= 150, range: '20 – 150 ppm'    },
    { label: 'Dureza cálcica',        unit: 'ppm', field: 'dureza', dec: 0, ok: e => e.dureza == null || (e.dureza >= 200 && e.dureza <= 700), range: '200 – 700 ppm'  },
    { label: 'Estabilizador (CYA)',    unit: 'ppm', field: 'cya',    dec: 0, ok: e => e.cya == null || (e.cya >= 0 && e.cya <= 75), range: '0 – 75 ppm' },
    { label: 'Transparencia / Turbiedad', unit: 'UNT', field: 'turb', dec: 2, ok: e => e.turb >= 0   && e.turb <= 0.5,  range: '0 – 0.5 UNT'    },
    { label: 'Temperatura del agua',  unit: '°C',   field: 'temp', dec: 1, ok: e => { const v = +e.temp; return isNaN(v) ? true : v <= 40; }, range: '≤ 40 °C'            },
    { label: 'Potencial redox (ORP)',  unit: 'mV',   field: 'orp',  dec: 0, ok: e => { const v = +e.orp;  return isNaN(v) ? true : v >= 0    && v <= 700;  }, range: '0 – 700 mV'         },
    { label: 'Sólidos disueltos (TDS)',unit: 'mg/L', field: 'tds',  dec: 0, ok: e => e.tds  == null || (e.tds  >= 1000 && e.tds  <= 1200), range: '1000 – 1200 mg/L'   },
    { label: 'Conductividad eléctrica',unit: 'µS/cm',field: 'cond', dec: 0, ok: e => e.cond == null || (e.cond >= 2000 && e.cond <= 2400), range: '2000 – 2400 µS/cm'  },
  ];

  doc.autoTable({
    startY: doc.lastAutoTable.finalY + 16,
    head: [['Parámetro', 'Rango normativo', 'Promedio', 'Mín', 'Máx', '% en rango']],
    body: [
      [{ content: `Mediciones: ${log.length}   ·   Incidentes AFR: ${incidents.length}`, colSpan: 6, styles: { fontStyle: 'bold', halign: 'center' } }],
      ...paramRows.map(p => {
        const a  = _avg(p.field);
        const mn = _min(p.field);
        const mx = _max(p.field);
        const pc = _pct(p.ok);
        return [
          p.label,
          p.range,
          a  != null ? _fmt(a,  p.dec) + (p.unit ? ' ' + p.unit : '') : '–',
          mn != null ? _fmt(mn, p.dec) : '–',
          mx != null ? _fmt(mx, p.dec) : '–',
          pc != null ? pc + '%' : '–',
        ];
      }),
    ],
    theme: 'grid',
    headStyles: { fillColor: [12, 184, 106], textColor: 255, fontStyle: 'bold' },
    styles:     { fontSize: 9 },
    columnStyles: {
      0: { cellWidth: 50 },
      1: { cellWidth: 30, halign: 'center' },
      2: { cellWidth: 28, halign: 'center' },
      3: { cellWidth: 16, halign: 'center' },
      4: { cellWidth: 16, halign: 'center' },
      5: { cellWidth: 42, halign: 'center' },
    },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 5 && data.row.index >= 1) {
        const n = parseInt(data.cell.raw);
        if (!isNaN(n)) {
          data.cell.styles.fontStyle = 'bold';
          data.cell.styles.fillColor = n >= 80 ? [220, 252, 231] : n >= 50 ? [254, 243, 199] : [254, 226, 226];
        }
      }
    },
    margin: { left: 14, right: 14 },
  });

  // ── IRAPI 2026 — calculado desde los 20 registros ────────
  {
    const n       = log.length;
    const ncCloro = log.filter(e =>
      (e.cloro != null && !isNaN(e.cloro) && (e.cloro < 2.0 || e.cloro > 4.0)) ||
      (e.clorocomb != null && !isNaN(e.clorocomb) && e.clorocomb > 0.3)
    ).length;
    const ncAlk   = log.filter(e =>
      (e.alc != null && !isNaN(e.alc) && (e.alc < 20  || e.alc > 150)) ||
      (e.ph  != null && !isNaN(e.ph)  && (e.ph  < 6.8 || e.ph  > 7.3))
    ).length;
    const ncOtros = log.filter(e =>
      (e.turb != null && !isNaN(e.turb) && e.turb > 0.5) ||
      (e.cya  != null && !isNaN(e.cya)  && e.cya  > 75)  ||
      (e.orp  != null && !isNaN(e.orp)  && (e.orp < 650 || e.orp > 700))
    ).length;
    const pCloro  = Math.round((ncCloro / n) * 100);
    const pAlk    = Math.round((ncAlk   / n) * 100);
    const pOtros  = Math.round((ncOtros / n) * 100);
    // Microbiológico no disponible desde bitácora — se normaliza sobre el 55% medible
    const irapiScore = +(pCloro * (20/55) + pAlk * (30/55) + pOtros * (5/55)).toFixed(1);
    let irapiLabel = 'Sin riesgo (parcial)';
    if (irapiScore > 75)      irapiLabel = 'Alto (parcial)';
    else if (irapiScore > 35) irapiLabel = 'Medio (parcial)';
    else if (irapiScore > 10) irapiLabel = 'Bajo (parcial)';
    const scoreColor = irapiScore <= 10 ? [220, 252, 231] : irapiScore <= 35 ? [254, 243, 199] : irapiScore <= 75 ? [255, 237, 213] : [254, 226, 226];

    const pageH  = doc.internal.pageSize.getHeight();
    let irapiY = doc.lastAutoTable.finalY + 12;
    if (irapiY + 50 > pageH - 15) { doc.addPage(); irapiY = 20; }

    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 41, 59);
    doc.text('IRAPI 2026 — Índice de Riesgo Acumulado de Piscinas', 14, irapiY);

    doc.autoTable({
      startY: irapiY + 4,
      head: [['Parámetro', '% No conformidad', 'Peso', 'Aporte al score']],
      body: [
        ['Microbiológico *', 'No determinado', '45%', '–'],
        ['Cloro residual',   pCloro + '%',    '20% (36% s/micro)', (pCloro * (20/55)).toFixed(1)],
        ['Alcalinidad / pH', pAlk   + '%',    '30% (55% s/micro)', (pAlk   * (30/55)).toFixed(1)],
        ['Otros parámetros', pOtros + '%',    '5% (9% s/micro)',   (pOtros * (5/55)).toFixed(1)],
        ['Nivel de riesgo (parcial)', irapiScore.toString(), '', irapiLabel],
      ],
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: 255, fontStyle: 'bold' },
      styles:     { fontSize: 9 },
      columnStyles: { 1: { halign: 'center' }, 2: { halign: 'center' }, 3: { halign: 'center' } },
      didParseCell: (data) => {
        if (data.section === 'body' && data.row.index === 4) {
          data.cell.styles.fontStyle = 'bold';
          data.cell.styles.fillColor = scoreColor;
        }
      },
      margin: { left: 14, right: 14 },
    });

    doc.setFontSize(7.5);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(120);
    doc.text('* Microbiológico requiere laboratorio certificado (Res. 234/2026). No evaluado en este período — índice calculado sobre el 55% de parámetros medibles (pesos normalizados).', 14, doc.lastAutoTable.finalY + 5);
  }

  // ── Bitácora ─────────────────────────────────────────────
  if (log.length > 0) {
    const pageH = doc.internal.pageSize.getHeight();
    let bitY = doc.lastAutoTable.finalY + 12;
    if (bitY + 40 > pageH - 15) { doc.addPage(); bitY = 20; }

    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 41, 59);
    doc.text('Registros de la bitácora', 14, bitY);

    doc.autoTable({
      startY: bitY + 4,
      head: [['Fecha', 'Hora', 'Operador', 'Cl.Libre', 'Cl.Comb', 'pH', 'Alc.', 'CYA', 'Turb.', 'Temp.', 'ORP', 'Bañistas', 'Notas']],
      body: log.map(e => [
        e.fecha    || '–',
        fmt12h(e.hora),
        e.operador || '–',
        (e.cloro     ?? '–') + ' ppm',
        (e.clorocomb != null && !isNaN(e.clorocomb) ? e.clorocomb + ' ppm' : '–'),
        e.ph       ?? '–',
        (e.alc  ?? '–') + ' ppm',
        (e.cya  ?? '–') + ' ppm',
        (e.turb ?? '–') + ' UNT',
        (e.temp ?? '–') + ' °C',
        (e.orp  != null && !isNaN(e.orp) ? e.orp + ' mV' : '–'),
        e.banistas ?? '–',
        e.notas    || '',
      ]),
      theme: 'striped',
      headStyles: { fillColor: [30, 41, 59], textColor: 255, fontStyle: 'bold' },
      styles:     { fontSize: 6.5, cellPadding: 1.0 },
      columnStyles: { 12: { cellWidth: 28 } },
      margin: { left: 14, right: 14 },
    });
  }

  // ── Incidentes AFR ───────────────────────────────────────
  const afrPageH = doc.internal.pageSize.getHeight();
  let afrY = doc.lastAutoTable ? doc.lastAutoTable.finalY + 12 : 20;
  if (afrY + 40 > afrPageH - 15) { doc.addPage(); afrY = 20; }

  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 41, 59);
  doc.text('Protocolo AFR — Incidentes del periodo', 14, afrY);

  if (incidents.length === 0) {
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100);
    doc.text('Sin incidentes AFR registrados en este periodo.', 14, afrY + 8);
  } else {
    doc.autoTable({
      startY: afrY + 4,
      head: [['Fecha', 'Hora', 'Tipo / Severidad', 'Operador', 'Cl. final', 'pH final', 'Turb. final', 'Reapertura']],
      body: incidents.map(i => {
        const reapertura = i.fechaReapertura
          ? `${i.fechaReapertura}${i.horaReapertura ? ' ' + fmt12h(i.horaReapertura) : ''}`
          : '–';
        return [
          i.fecha    || '–',
          fmt12h(i.hora),
          i.tipo === 'diarreico' ? 'Diarreico — EMERGENCIA (Cryptosporidium)' : i.tipo === 'vomito' ? 'Vómito' : 'Sólido',
          i.operador || '–',
          i.cloroFinal  != null ? `${i.cloroFinal} ppm`             : '–',
          i.phFinal     != null ? String(i.phFinal)                  : '–',
          i.turbFinal   != null ? `${i.turbFinal} UNT`               : '–',
          reapertura,
        ];
      }),
      theme: 'grid',
      headStyles: { fillColor: [153, 27, 27], textColor: 255, fontStyle: 'bold', fontSize: 8 },
      bodyStyles: { fontSize: 8 },
      columnStyles: { 2: { cellWidth: 40 }, 6: { cellWidth: 18 } },
      didParseCell: (data) => {
        if (data.section !== 'body') return;
        const tipo = incidents[data.row.index]?.tipo;
        if (tipo === 'diarreico') {
          data.cell.styles.fillColor = [254, 226, 226];
          data.cell.styles.textColor = [153, 27, 27];
          if (data.column.index === 2) data.cell.styles.fontStyle = 'bold';
        } else if (tipo === 'vomito') {
          data.cell.styles.fillColor = [254, 243, 199];
        }
      },
      margin: { left: 14, right: 14 },
    });
  }

  // ── Sección de verificación de integridad ────────────────
  {
    const pageH = doc.internal.pageSize.getHeight();
    let vY = doc.lastAutoTable ? doc.lastAutoTable.finalY + 14 : 20;
    if (vY + 38 > pageH - 20) { doc.addPage(); vY = 20; }

    const integrityOk  = integrity?.clean !== false;
    const headerColor  = integrityOk ? [12, 184, 106] : [220, 38, 38];
    const headerLabel  = integrityOk
      ? 'Verificación de integridad — OK'
      : '⚠ Advertencia de integridad — datos posiblemente modificados';

    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...headerColor);
    doc.text(headerLabel, 14, vY);

    doc.autoTable({
      startY: vY + 4,
      body: [
        ['Fecha y hora de generación', genLocal],
        ['SHA-256 bitácora (primeros/últimos bytes)', hashShort],
        ['Origen de los datos', 'Brazada Aqua Tech — almacenamiento local del dispositivo (localStorage)'],
        ['Verificación HMAC', integrityOk ? 'Firmas válidas — no se detectaron modificaciones externas' : `Falla de integridad detectada en: ${integrity.tampered.map(c => c.key).join(', ')}`],
        ['Advertencia legal', 'Este documento fue generado por una aplicación cliente. No constituye un registro oficial certificado por autoridad sanitaria. La integridad de los datos depende del dispositivo y del navegador del operador.'],
      ],
      theme: 'plain',
      styles:      { fontSize: 8, cellPadding: 2 },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 60, textColor: [100, 116, 139] },
        1: { cellWidth: 126 },
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.row.index === 3) {
          data.cell.styles.textColor = integrityOk ? [22, 101, 52] : [185, 28, 28];
          data.cell.styles.fontStyle = 'bold';
        }
        if (data.section === 'body' && data.row.index === 4) {
          data.cell.styles.textColor = [120, 120, 120];
          data.cell.styles.fontStyle = 'italic';
        }
      },
      margin: { left: 14, right: 14 },
    });
  }

  // ── Pie de página ────────────────────────────────────────
  const pages = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setFontSize(7.5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(150);
    doc.text(
      `Brazada Aqua Tech · Res. 234 / 2026 · Página ${i} de ${pages}`,
      105, doc.internal.pageSize.getHeight() - 8,
      { align: 'center' }
    );
  }

  doc.save(`Reporte_Mensual_${nombre.replace(/\s+/g, '_')}_${desde || 'sin-fecha'}.pdf`);
  showToast('PDF generado correctamente.', 'success');
}

// ── DOCUMENTOS Y CUMPLIMIENTO ────────────────────────────
const DOCS_ITEMS = [
  { id: 'doc-res234',     label: 'Resolución 234 / 2026',          category: 'Normativos', publicOnly: false },
  { id: 'doc-ley1209',    label: 'Ley 1209 / 2008',                category: 'Normativos', publicOnly: false },
  { id: 'doc-dec780',     label: 'Decreto 780 / 2016',             category: 'Normativos', publicOnly: false },
  { id: 'doc-bitacora',   label: 'Bitácora sistematizada',          category: 'Operativos', publicOnly: false },
  { id: 'doc-lab',        label: 'Registros de laboratorio',        category: 'Operativos', publicOnly: true  },
  { id: 'doc-quimicos',   label: 'Certificados de químicos (SGA)',  category: 'Operativos', publicOnly: true  },
  { id: 'doc-botiquin',   label: 'Botiquín · Anexo III Res. 234',   category: 'Operativos', publicOnly: true  },
  { id: 'doc-salvavidas', label: 'Certificación del salvavidas',    category: 'Operativos', publicOnly: true  },
  { id: 'doc-equipos',    label: 'Mantenimiento de equipos',        category: 'Operativos', publicOnly: false },
  { id: 'doc-concepto',   label: 'Concepto sanitario vigente',      category: 'Operativos', publicOnly: true  },
];

function getDocsState() {
  try { return JSON.parse(localStorage.getItem('aqua_docs')) || {}; }
  catch { return {}; }
}

function getDocsProfile() {
  return localStorage.getItem('aqua_docs_profile') || 'publico';
}

function setDocsProfile(profile) {
  localStorage.setItem('aqua_docs_profile', profile);
  document.getElementById('btnPublico').classList.toggle('active', profile === 'publico');
  document.getElementById('btnDomestico').classList.toggle('active', profile === 'domestico');
  const vencEl = document.getElementById('cardVencimientos');
  if (vencEl) vencEl.style.display = profile === 'publico' ? '' : 'none';
  renderDocs();
}

function toggleDocItem(id) {
  const state = getDocsState();
  state[id] = !state[id];
  localStorage.setItem('aqua_docs', JSON.stringify(state));
  renderDocs();
}

function renderDocs() {
  const state      = getDocsState();
  const profile    = getDocsProfile();
  const visible    = DOCS_ITEMS.filter(i => profile === 'publico' || !i.publicOnly);
  const checked    = visible.filter(i => state[i.id]).length;
  const categories = [...new Set(visible.map(i => i.category))];

  const wrap = document.getElementById('docsChecklist');
  if (!wrap) return;

  const CHECK_ICON = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;

  wrap.innerHTML = categories.map(cat => `
    <div class="docs-category">
      <div class="docs-category-label">${cat}</div>
      ${visible.filter(i => i.category === cat).map(item => `
        <div class="docs-item ${state[item.id] ? 'checked' : ''}" data-doc-id="${item.id}">
          <div class="docs-item-check">${state[item.id] ? CHECK_ICON : ''}</div>
          <span class="docs-item-label">${item.label}</span>
        </div>
      `).join('')}
    </div>
  `).join('');

  const pct    = visible.length ? (checked / visible.length) * 100 : 0;
  const fillEl = document.getElementById('docsProgressFill');
  const textEl = document.getElementById('docsProgressText');
  if (fillEl) {
    fillEl.style.width      = pct + '%';
    fillEl.style.background = pct === 100 ? '#0cb86a' : pct >= 60 ? '#f59e0b' : '#ef4444';
  }
  if (textEl) textEl.textContent = `${checked} / ${visible.length}`;
}

function applyConcepto(val) {
  document.querySelectorAll('.concepto-opt').forEach(b => {
    b.classList.toggle('active', b.dataset.val === val);
  });
}

function selectConcepto(val) {
  const dates = JSON.parse(localStorage.getItem('aqua_docs_dates') || '{}');
  dates['concepto'] = val;
  localStorage.setItem('aqua_docs_dates', JSON.stringify(dates));
  applyConcepto(val);
  renderDashboardVencimientos();
}

function updateVencimientos() {
  const pairs = [
    { inputId: 'fechaSalvavidas', statusId: 'statusSalvavidas' },
  ];

  const dates = JSON.parse(localStorage.getItem('aqua_docs_dates') || '{}');
  pairs.forEach(({ inputId }) => {
    const el = document.getElementById(inputId);
    if (el) dates[inputId] = el.value;
  });
  localStorage.setItem('aqua_docs_dates', JSON.stringify(dates));

  pairs.forEach(({ inputId, statusId }) => {
    const input    = document.getElementById(inputId);
    const statusEl = document.getElementById(statusId);
    if (!input || !statusEl) return;
    if (!input.value) { statusEl.textContent = '–'; statusEl.className = 'docs-venc-status'; return; }

    const days = Math.ceil((new Date(input.value + 'T00:00:00') - new Date()) / 86400000);

    if (days < 0) {
      statusEl.textContent = 'Vencido';
      statusEl.className   = 'docs-venc-status status-danger';
    } else if (days <= 10) {
      statusEl.textContent = `${days} días`;
      statusEl.className   = 'docs-venc-status status-danger';
    } else if (days <= 30) {
      statusEl.textContent = `${days} días`;
      statusEl.className   = 'docs-venc-status status-warning';
    } else {
      statusEl.textContent = 'Vigente';
      statusEl.className   = 'docs-venc-status status-ok';
    }
  });
}

function initDocs() {
  const profile = getDocsProfile();
  document.getElementById('btnPublico').classList.toggle('active', profile === 'publico');
  document.getElementById('btnDomestico').classList.toggle('active', profile === 'domestico');

  const vencEl = document.getElementById('cardVencimientos');
  if (vencEl) vencEl.style.display = profile === 'publico' ? '' : 'none';

  try {
    const dates = JSON.parse(localStorage.getItem('aqua_docs_dates')) || {};
    Object.entries(dates).forEach(([id, val]) => {
      const el = document.getElementById(id);
      if (el) el.value = val;
    });
    if (dates['concepto']) applyConcepto(dates['concepto']);
  } catch {}

  renderDocs();
  updateVencimientos();
}

// ── INICIALIZACIÓN ────────────────────────────────────────
function initDateTimeFields() {
  const now  = new Date();
  const date = localDateStr(now);
  const time = now.toTimeString().slice(0, 5);

  const dateEl = document.getElementById('logDate');
  const timeEl = document.getElementById('logTime');
  if (dateEl) dateEl.value = date;
  if (timeEl) timeEl.value = time;
}

document.addEventListener('DOMContentLoaded', async () => {
  _pinInit();                    // Muestra overlay de PIN antes que cualquier otra cosa
  await _verifyIntegrity();      // Espera la verificación de integridad antes de renderizar datos

  // Sección visible — necesario para el primer paint
  renderDashboardGauges();
  renderDashboardIndices();
  renderDashboardVencimientos();
  initDateTimeFields();
  renderLog();
  checkLogForm();
  updateOperadorDatalist();
  updateDashReportBtn();

  // Secciones ocultas diferidas para reducir el bloqueo del hilo principal (TBT)
  setTimeout(() => {
    renderAFR();
    renderAFRIncidents();
    renderMnt();
    clearMntForm();
    restoreCalcFields();
    calcVolume();
    calcDosificacion();
    restoreLSIFields();
    calcLSI();
    restoreIRAPISliders();
    calcIRAPI();
    updateIRAPIBitacoraBtn();
    updateReportBtn();
    updateDashReportBtn();
    initDocs();
    restoreReportFields();
    ['sliderMicro','sliderCloro','sliderAlk','sliderOtros'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.setProperty('--pct', el.value + '%');
    });
  }, 0);

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      // No bloquear si la cámara/galería del OS está abierta
      if (_PIN.exists() && _PIN.unlocked && !_photoPickerActive) lockApp();
    } else {
      // App vuelve al frente: limpiar bandera (cubre el caso de cancelar sin foto)
      if (_photoPickerActive) setTimeout(() => { _photoPickerActive = false; }, 300);
    }
  });
});

// ── MANTENIMIENTO DE EQUIPOS ─────────────────────────────

function _isValidMntEntry(e) {
  return e !== null && typeof e === 'object'
    && typeof e.ts          === 'number' && isFinite(e.ts)
    && typeof e.fecha       === 'string' && e.fecha.length > 0
    && typeof e.tecnico     === 'string' && e.tecnico.length > 0
    && ['motobomba', 'caldera'].includes(e.area)
    && typeof e.descripcion === 'string' && e.descripcion.length > 0;
}

function getMntLog() {
  if (!_requireUnlocked()) return [];
  try {
    const raw = JSON.parse(localStorage.getItem('aqua_mantenimiento') || '[]');
    return Array.isArray(raw) ? raw.filter(_isValidMntEntry) : [];
  } catch { return []; }
}

function clearMntForm() {
  const now = new Date();
  const d = document.getElementById('mntFecha');
  if (d) d.value = localDateStr(now);
  ['mntTecnico', 'mntDescripcion'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const area = document.getElementById('mntArea');
  if (area) area.value = '';
  const prox = document.getElementById('mntProximo');
  if (prox) prox.value = '';
  _applyPhoto('mantenimientoFoto', null);
  checkMntForm();
}

function checkMntForm() {
  const ok = !!(
    document.getElementById('mntFecha')?.value.trim() &&
    document.getElementById('mntTecnico')?.value.trim() &&
    document.getElementById('mntArea')?.value &&
    document.getElementById('mntDescripcion')?.value.trim()
  );
  const btn = document.getElementById('btnSaveMnt');
  if (btn) btn.disabled = !ok;
}

function saveMnt() {
  if (!_requireUnlocked()) return;
  const fecha = document.getElementById('mntFecha').value.trim();
  const tec   = document.getElementById('mntTecnico').value.trim();
  const area  = document.getElementById('mntArea').value;
  const desc  = document.getElementById('mntDescripcion').value.trim();
  const prox  = document.getElementById('mntProximo').value.trim();
  if (!fecha || !tec || !area || !desc) return;

  const areaLabel = area === 'motobomba' ? 'Motobomba' : 'Caldera';
  let log = getMntLog();
  let toastMsg;

  if (editingMntTs) {
    const entry = { ts: editingMntTs, fecha, tecnico: tec, area, descripcion: desc,
                    proximo: prox || null, foto: _photos.mantenimientoFoto || null };
    log = log.map(e => e.ts === editingMntTs ? entry : e);
    editingMntTs = null;
    document.getElementById('btnSaveMntText').textContent   = 'Guardar registro';
    document.getElementById('mntEditBanner').style.display  = 'none';
    document.getElementById('btnCancelEditMnt').style.display = 'none';
    toastMsg = `Mantenimiento de ${areaLabel} actualizado.`;
  } else {
    const entry = { ts: Date.now(), fecha, tecnico: tec, area, descripcion: desc,
                    proximo: prox || null, foto: _photos.mantenimientoFoto || null };
    log.unshift(entry);
    toastMsg = `Mantenimiento de ${areaLabel} registrado.`;
  }

  _secSave('aqua_mantenimiento', JSON.stringify(log));
  _checkStorageUsage();
  clearMntForm();
  renderMnt();
  showToast(toastMsg, 'success');
}

function deleteMnt(ts) {
  if (!_requireUnlocked()) return;
  showConfirm('¿Eliminar este registro de mantenimiento? Esta acción no se puede deshacer.', () => {
    const log = getMntLog().filter(e => e.ts !== ts);
    _secSave('aqua_mantenimiento', JSON.stringify(log));
    renderMnt();
    showToast('Registro de mantenimiento eliminado.', 'success');
  });
}

function editMnt(ts) {
  if (!_requireUnlocked()) return;
  const e = getMntLog().find(x => x.ts === ts);
  if (!e) return;
  editingMntTs = ts;
  document.getElementById('mntFecha').value       = e.fecha       || '';
  document.getElementById('mntTecnico').value     = e.tecnico     || '';
  document.getElementById('mntArea').value        = e.area        || '';
  document.getElementById('mntDescripcion').value = e.descripcion || '';
  document.getElementById('mntProximo').value     = e.proximo     || '';
  _applyPhoto('mantenimientoFoto', e.foto || null);
  document.getElementById('btnSaveMntText').textContent     = 'Actualizar registro';
  document.getElementById('mntEditDate').textContent        = e.fecha || '';
  document.getElementById('mntEditBanner').style.display    = 'flex';
  document.getElementById('btnCancelEditMnt').style.display = 'inline-flex';
  checkMntForm();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function cancelEditMnt() {
  editingMntTs = null;
  document.getElementById('btnSaveMntText').textContent     = 'Guardar registro';
  document.getElementById('mntEditBanner').style.display    = 'none';
  document.getElementById('btnCancelEditMnt').style.display = 'none';
  clearMntForm();
}

function renderMnt() {
  if (!_requireUnlocked()) return;
  const log  = getMntLog();
  const wrap = document.getElementById('mntListWrap');
  const cnt  = document.getElementById('mntCount');
  if (!wrap) return;
  if (cnt) cnt.textContent = log.length;
  if (!log.length) {
    wrap.innerHTML = '<p class="empty-state">Sin registros aún. Agregue el primer mantenimiento.</p>';
    return;
  }
  wrap.innerHTML = log.map(e => {
    const isMoto     = e.area === 'motobomba';
    const badgeClass = isMoto ? 'mnt-badge-motobomba' : 'mnt-badge-caldera';
    const badgeText  = isMoto ? 'Motobomba' : 'Caldera';
    const proxTxt    = e.proximo ? ` · Próximo: ${escapeHtml(e.proximo)}` : '';
    const hasPhoto   = !!_safePhotoSrc(e.foto);
    return `
    <div class="mnt-item" data-ts="${e.ts}" title="Ver detalle del mantenimiento">
      <div class="mnt-item-info">
        <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
        <div>
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:2px">
            <strong>${escapeHtml(e.fecha)}</strong>
            <span class="mnt-area-badge ${badgeClass}">${badgeText}</span>
            ${hasPhoto ? `<svg title="Foto adjunta" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>` : ''}
          </div>
          <span style="font-size:13px;color:var(--text-muted)">Técnico: ${escapeHtml(e.tecnico)}${proxTxt}</span>
        </div>
      </div>
      <div class="mnt-item-actions">
        <button class="btn-edit-log" title="Editar registro" aria-label="Editar registro de mantenimiento">
          <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </button>
        <button class="btn-delete-log" title="Eliminar registro" aria-label="Eliminar registro de mantenimiento">
          <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
        </button>
      </div>
    </div>`;
  }).join('');
}

function openMntDetail(ts) {
  if (!_requireUnlocked()) return;
  const e = getMntLog().find(x => x.ts === ts);
  if (!e) return;

  const overlay = document.getElementById('mntDetailOverlay');
  const title   = document.getElementById('mntDetailTitle');
  const meta    = document.getElementById('mntDetailMeta');
  const body    = document.getElementById('mntDetailBody');
  if (!overlay || !body) return;

  const isMoto     = e.area === 'motobomba';
  const badgeClass = isMoto ? 'mnt-badge-motobomba' : 'mnt-badge-caldera';
  const badgeText  = isMoto ? 'Motobomba' : 'Caldera';

  if (title) title.innerHTML = `Mantenimiento &middot; <span class="mnt-area-badge ${badgeClass}">${badgeText}</span>`;
  if (meta)  meta.textContent = e.fecha + (e.proximo ? ' · Próximo: ' + e.proximo : '');

  const fotoHTML = _safePhotoSrc(e.foto) ? `
    <div class="log-detail-section">
      <div class="log-detail-section-title">Foto del mantenimiento</div>
      <div class="log-detail-fotos">
        <div class="log-detail-foto-item">
          <img class="log-detail-foto-img" src="${_safePhotoSrc(e.foto)}" alt="Foto del mantenimiento" />
        </div>
      </div>
    </div>` : '';

  body.innerHTML = `
    <div class="log-detail-section">
      <div class="log-detail-section-title">Técnico</div>
      <p style="margin:0;font-size:15px;font-weight:600;color:var(--text)">${escapeHtml(e.tecnico)}</p>
    </div>
    <div class="log-detail-section">
      <div class="log-detail-section-title">Descripción del trabajo</div>
      <p style="margin:0;font-size:13px;line-height:1.65;color:var(--text)">${escapeHtml(e.descripcion)}</p>
    </div>
    ${fotoHTML}
    <div style="display:flex;gap:8px;margin-top:20px;flex-wrap:wrap">
      <button class="btn btn-outline btn-danger-outline js-mnt-detail-delete" style="flex:1">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
        Eliminar
      </button>
      <button class="btn btn-outline js-mnt-detail-edit" style="flex:1">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        Editar
      </button>
      <button class="btn btn-primary js-mnt-detail-close" style="flex:1">Cerrar</button>
    </div>
  `;

  body.querySelector('.js-mnt-detail-delete').addEventListener('click', () => { closeMntDetail(); deleteMnt(e.ts); });
  body.querySelector('.js-mnt-detail-edit').addEventListener('click',   () => { closeMntDetail(); editMnt(e.ts); });
  body.querySelector('.js-mnt-detail-close').addEventListener('click',  () => closeMntDetail());

  overlay.style.display = 'flex';
  document.body.style.overflow = 'hidden';
}

function closeMntDetail(event) {
  if (event && event.target !== document.getElementById('mntDetailOverlay')) return;
  const overlay = document.getElementById('mntDetailOverlay');
  if (overlay) overlay.style.display = 'none';
  document.body.style.overflow = '';
}

// ── PRELOADER ─────────────────────────────────────────────
function preloaderNext() {
  const s1    = document.getElementById('preloaderScreen1');
  const s2    = document.getElementById('preloaderScreen2');
  const chip  = document.querySelector('.preloader-jg-chip');
  const video = document.querySelector('.preloader-avatar');
  if (!s1 || !s2) return;

  // Mover el video al header del screen 2 como avatar circular
  if (video && chip) {
    video.classList.add('preloader-avatar-sm');
    chip.replaceWith(video);
    // En PC el movimiento del nodo DOM puede pausar el video; forzar reproducción
    video.play().catch(() => {});
  }

  s1.classList.add('screen-exit');
  setTimeout(() => {
    s1.style.display = 'none';
    s2.style.display = 'flex';
    s2.removeAttribute('aria-hidden');
    requestAnimationFrame(() => s2.classList.add('screen-enter'));
  }, 280);
}

function dismissPreloader(section) {
  const el = document.getElementById('preloader');
  if (!el) return;
  el.classList.add('fade-out');
  setTimeout(() => {
    el.remove();
    if (section && section !== 'dashboard') navigate(section);
  }, 420);
}

(function initPreloader() {
  setTimeout(() => {
    const dots = document.getElementById('preloaderDots');
    const btn  = document.getElementById('preloaderBtn');
    if (dots) dots.style.display = 'none';
    if (btn)  btn.style.display  = 'flex';
  }, 7000);
}());