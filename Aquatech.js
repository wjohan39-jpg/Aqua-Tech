'use strict';

// Prevent clickjacking by redirecting the parent frame when possible.
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

// Convert a value from storage into a safe numeric display.
function _safeNum(v, fix) {
  const n = Number(v);
  if (!isFinite(n)) return '–';
  return fix !== undefined ? n.toFixed(fix) : String(n);
}

// Only allow safe image data URIs for photo rendering.
function _safePhotoSrc(v) {
  if (typeof v !== 'string') return '';
  if (v.startsWith('data:image/jpeg;base64,') || v.startsWith('data:image/png;base64,')) return v;
  return '';
}

const STORAGE_KEYS = Object.freeze({
  pin: 'aqua_pin',
  pinState: '_pin_state',
  bitacora: 'aqua_bitacora',
  afr: 'aqua_afr',
  mantenimiento: 'aqua_mantenimiento',
  lab: 'aqua_lab',
  visitas: 'aqua_visitas',
  reporte: 'aqua_reporte',
  docs: 'aqua_docs',
  docsDates: 'aqua_docs_dates',
  docsProfile: 'aqua_docs_profile',
  perfil: 'aqua_perfil',
  botiquin: 'aqua_botiquin',
  config: 'aqua_config',
  calc: 'aqua_calc',
  theme: 'aqua_theme'
});

const PIN_VIEW_IDS = Object.freeze(['pinViewSetup', 'pinViewUnlock', 'pinViewChange']);
const PIN_INPUT_IDS = Object.freeze(['pinSetupNew', 'pinSetupConfirm', 'pinUnlockInput', 'pinChangeOld', 'pinChangeNew', 'pinChangeConfirm']);
const PIN_ERROR_IDS = Object.freeze(['pinSetupError', 'pinUnlockError', 'pinChangeError']);

// Integrity protection for stored data.
const _INTEGRITY = (() => {
  const DB    = 'aquatech_integrity_v1';
  const STORE = 'keys';
  const KID   = 'hmac_k';
  let _cache  = null;

  function _openDb() {
    return new Promise((res, rej) => {
      const r = indexedDB.open(DB, 1);
      r.onupgradeneeded = e => {
        e.target.result.createObjectStore(STORE);
        localStorage.setItem('aqua_key_reset', '1');
      };
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

// PIN-based session protection.
const _PIN = (() => {
  const KEY   = STORAGE_KEYS.pin;
  const ITERS = 600_000;   // OWASP 2024: mínimo 600k para PBKDF2-HMAC-SHA-256
  const HASH  = 'SHA-256';
  const BITS  = 256;

  // Estado de sesión privado
  let _unlocked    = false;
  let _attempts    = 0;
  let _lockedUntil = 0;
  let _sessionKey  = null;

  const _SS_KEY = STORAGE_KEYS.pinState;
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
    if (diff === 0) _sessionKey = actual;
    return diff === 0;
  }

  function exists() { return !!localStorage.getItem(KEY); }
  function remove() { localStorage.removeItem(KEY); _sessionKey = null; }

  function getSessionKey() { return _sessionKey; }

  // Interfaz de sesión — acceso controlado al estado privado
  function unlock()       { _unlocked = true; _attempts = 0; _lockedUntil = 0; _saveAttemptState(); }
  function lock()         { _unlocked = false; _sessionKey = null; }
  function addAttempt()   { ++_attempts; _saveAttemptState(); return _attempts; }
  function setLockout(ms) { _lockedUntil = Date.now() + ms; _saveAttemptState(); }
  function remainingSecs(){ return Math.max(0, Math.ceil((_lockedUntil - Date.now()) / 1000)); }

  return {
    set, verify, exists, remove,
    unlock, lock, addAttempt, setLockout, remainingSecs, getSessionKey,
    get unlocked()  { return _unlocked;  },
    get attempts()  { return _attempts;  },
  };
})();

const _SECURE_STORE = (() => {
  const PROTECTED_KEYS = new Set([
    STORAGE_KEYS.bitacora,
    STORAGE_KEYS.afr,
    STORAGE_KEYS.mantenimiento,
    STORAGE_KEYS.lab,
    STORAGE_KEYS.visitas,
    STORAGE_KEYS.reporte,
    STORAGE_KEYS.docs,
    STORAGE_KEYS.docsDates,
    STORAGE_KEYS.docsProfile,
    STORAGE_KEYS.perfil,
    STORAGE_KEYS.botiquin,
    STORAGE_KEYS.config,
    STORAGE_KEYS.calc,
    STORAGE_KEYS.theme
  ]);
  const CACHE = new Map();
  const PREFIX = '__aqua_enc__';
  let originalGetItem = null;
  let originalSetItem = null;
  let originalRemoveItem = null;

  function _b64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
  function _fromB64(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }

  function _serializeValue(value) {
    return typeof value === 'string' ? value : JSON.stringify(value);
  }

  function _parseValue(value) {
    if (value == null) return null;
    if (typeof value === 'string') {
      try { return JSON.parse(value); } catch { return value; }
    }
    return value;
  }

  async function _encryptText(text, keyBytes) {
    if (!keyBytes) return null;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey('raw', new Uint8Array(keyBytes), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
    return { v: 1, iv: _b64(iv), ct: _b64(new Uint8Array(data)) };
  }

  async function _decryptText(blob, keyBytes) {
    if (!keyBytes || !blob || !blob.v || !blob.iv || !blob.ct) return null;
    const key = await crypto.subtle.importKey('raw', new Uint8Array(keyBytes), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: _fromB64(blob.iv) }, key, _fromB64(blob.ct));
    return new TextDecoder().decode(plain);
  }

  const _pending = new Set();

  async function _persistInternal(key, value) {
    const keyBytes = _PIN.getSessionKey();
    if (!keyBytes) return;
    const text = _serializeValue(value);
    const payload = await _encryptText(text, keyBytes);
    if (!payload) return;
    try {
      originalSetItem.call(localStorage, key, PREFIX + JSON.stringify(payload));
    } catch (e) {
      if (e.name === 'QuotaExceededError' || e.name === 'NS_ERROR_DOM_QUOTA_REACHED') {
        showToast('Almacenamiento lleno. Elimina fotos o registros antiguos para continuar.', 'error', 8000);
      }
      return;
    }
    try {
      const sig = await _INTEGRITY.sign(text);
      originalSetItem.call(localStorage, key + '_sig', sig);
    } catch {}
  }

  async function _persist(key, value) {
    const p = _persistInternal(key, value);
    _pending.add(p);
    try { await p; } finally { _pending.delete(p); }
  }

  async function flush() {
    if (_pending.size === 0) return;
    await Promise.all([..._pending]);
  }

  async function init() {
    const keyBytes = _PIN.getSessionKey();
    for (const key of PROTECTED_KEYS) {
      const raw = localStorage.getItem(key);
      if (!raw) continue;
      if (CACHE.has(key)) continue;
      if (typeof raw === 'string' && raw.startsWith(PREFIX)) {
        try {
          const blob = JSON.parse(raw.slice(PREFIX.length));
          const plain = keyBytes ? await _decryptText(blob, keyBytes) : null;
          if (plain != null) CACHE.set(key, _parseValue(plain));
        } catch {}
      } else if (keyBytes) {
        try {
          CACHE.set(key, _parseValue(raw));
          void _persist(key, CACHE.get(key));
        } catch {}
      }
    }
  }

  function hasProtectedKey(key) { return typeof key === 'string' && PROTECTED_KEYS.has(key); }

  function getCached(key, fallback) {
    if (CACHE.has(key)) return CACHE.get(key);
    const raw = originalGetItem.call(localStorage, key);
    if (!raw) return fallback;
    if (typeof raw === 'string' && raw.startsWith(PREFIX)) return fallback;
    try { return _parseValue(raw); } catch { return fallback; }
  }

  function setCached(key, value) {
    const normalized = _serializeValue(value);
    if (!_PIN.getSessionKey()) return normalized;
    CACHE.set(key, _parseValue(normalized));
    void _persist(key, CACHE.get(key));
    return normalized;
  }

  function removeCached(key) {
    CACHE.delete(key);
    originalRemoveItem.call(localStorage, key);
    originalRemoveItem.call(localStorage, key + '_sig');
  }

  const storageProto = window.Storage?.prototype;
  if (storageProto && !storageProto.__aquatechSecurePatched) {
    originalGetItem = storageProto.getItem;
    originalSetItem = storageProto.setItem;
    originalRemoveItem = storageProto.removeItem;

    storageProto.getItem = function(key) {
      if (hasProtectedKey(key)) {
        const cached = getCached(key, null);
        if (cached !== null) return typeof cached === 'string' ? cached : JSON.stringify(cached);
      }
      return originalGetItem.call(this, key);
    };

    storageProto.setItem = function(key, value) {
      if (hasProtectedKey(key)) {
        setCached(key, value);
        return;
      }
      return originalSetItem.call(this, key, value);
    };

    storageProto.removeItem = function(key) {
      if (hasProtectedKey(key)) {
        removeCached(key);
        return;
      }
      return originalRemoveItem.call(this, key);
    };

    storageProto.__aquatechSecurePatched = true;
  }

  return { init, flush, hasProtectedKey, getCached, setCached, removeCached };
})();

function _pinSwitchView(view) {
  PIN_VIEW_IDS.forEach(id => {
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
  PIN_INPUT_IDS.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
}

function _pinClearErrors() {
  PIN_ERROR_IDS.forEach(id => {
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
  const okCreate = await _PIN.verify(newPin);
  if (okCreate) _PIN.unlock();
  await _SECURE_STORE.init();
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
    await _SECURE_STORE.init();
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
  const okChange = await _PIN.verify(newPin);
  if (okChange) _PIN.unlock();
  await _SECURE_STORE.init();
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
      indexedDB.deleteDatabase('aquatech_integrity_v1');
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

async function lockApp() {
  if (!_PIN.exists()) { showToast('No hay PIN configurado.', 'warning'); return; }
  await _SECURE_STORE.flush();
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

// Guarda json de forma protegida en localStorage y espera a que el cifrado confirme escritura en disco.
async function _secSave(lsKey, json) {
  try {
    localStorage.setItem(lsKey, json);  // interceptado → setCached → _persist en _pending
  } catch (e) {
    if (e.name === 'QuotaExceededError' || e.name === 'NS_ERROR_DOM_QUOTA_REACHED') {
      showToast('Almacenamiento lleno. Elimina fotos o registros antiguos para continuar.', 'error', 8000);
    }
    return;
  }
  await _SECURE_STORE.flush();  // Espera a que el cifrado AES-GCM escriba en localStorage real
  try {
    const sig = await _INTEGRITY.sign(json);
    localStorage.setItem(lsKey + '_sig', sig);
  } catch { /* fallo silencioso — dato guardado, firma omitida */ }
}

// Validate signatures for protected storage keys.
async function _verifyIntegrity() {
  const migrated = localStorage.getItem('aqua_key_reset') === '1';
  if (migrated) localStorage.removeItem('aqua_key_reset');

  for (const k of [STORAGE_KEYS.bitacora, STORAGE_KEYS.afr, STORAGE_KEYS.mantenimiento, STORAGE_KEYS.lab, STORAGE_KEYS.visitas]) {
    const raw = localStorage.getItem(k);
    const sig = localStorage.getItem(k + '_sig');
    if (!raw || !sig) continue;
    const payload = typeof raw === 'string' && raw.startsWith('__aqua_enc__')
      ? _SECURE_STORE.getCached(k, raw)
      : raw;
    const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
    if (migrated) {
      const newSig = await _INTEGRITY.sign(text);
      localStorage.setItem(k + '_sig', newSig);
      continue;
    }
    const ok = await _INTEGRITY.verify(text, sig);
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
  const renderers = {
    dashboard: () => {
      renderDashboardIndices();
      renderDashboardVencimientos();
      renderDashMntSchedule();
      renderDashboardGauges();
      updateDashReportBtn();
      _renderDashEstablishment();
      updateNavVencBadge();
    },
    reporte: () => {
      _prefillReporteFromPerfil();
      updateReportSummary();
      updateReportBtn();
    },
    calculadora: () => {
      calcVolume();
      calcDosificacion();
    },
    lsi: () => {
      _lsiFromBitacora = false;
      calcLSI();
    },
    irapi: () => {
      calcIRAPI();
      updateIRAPIBitacoraBtn();
      renderLabReg();
    },
    perfil: () => {
      renderPerfil();
    },
    documentos: () => {
      renderDocs();
      updateVencimientos();
      renderVencSaneamiento();
      renderBotiquinCard();
      renderVisitas();
      clearVisitaForm();
      updateNavVencBadge();
    },
    bitacora: () => {
      renderLog();
      updateOperadorDatalist();
      updateSalvavidasDatalist();
    },
    protocolo: () => {
      renderAFR();
      renderAFRIncidents();
    },
    mantenimiento: () => {
      renderMnt();
      renderSaneamiento();
      checkMntForm();
    }
  };

  const render = renderers[section];
  if (render) render();
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
    const jgPanel = document.getElementById('jgPanel');
    if (jgPanel && !jgPanel.hidden) { closeJGPanel(); return; }
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
  if (navEl) {
    const jgPanel = document.getElementById('jgPanel');
    if (jgPanel && !jgPanel.hidden) closeJGPanel();
    navigate(navEl.dataset.navigate, e);
    return;
  }

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
  if (t.closest('#btnGoLabReg'))          { document.getElementById('labRegCard')?.scrollIntoView({ behavior: 'smooth', block: 'start' }); return; }
  if (t.closest('#btnSaveLab'))           { saveLabRecord();          return; }
  if (t.closest('.btn-delete-lab'))       { deleteLabRecord(Number(t.closest('[data-ts]').dataset.ts)); return; }
  if (t.closest('#btnSavePerfil'))        { savePerfil();             return; }
  if (t.closest('#btnAddSalvavidas'))     { addSalvavidas();          return; }
  const svDelBtn = t.closest('.perfil-sv-del[data-sv-idx]');
  if (svDelBtn) { removeSalvavidas(Number(svDelBtn.dataset.svIdx)); return; }
  if (t.closest('#btnSaveBotiquin'))      { saveBotiquin();           return; }
  if (t.closest('#btnSaveVisita'))        { saveVisita();             return; }
  if (t.closest('#btnCancelVisita'))      { clearVisitaForm(); renderVisitas(); return; }
  const visitaEditBtn = t.closest('.visita-edit-btn[data-ts]');
  if (visitaEditBtn) { editVisita(Number(visitaEditBtn.dataset.ts)); return; }
  const visitaDelBtn  = t.closest('.visita-del-btn[data-ts]');
  if (visitaDelBtn)  { deleteVisita(Number(visitaDelBtn.dataset.ts)); return; }
  const visitaItem = t.closest('.visita-item[data-ts]');
  if (visitaItem && !t.closest('.visita-item-actions')) { viewVisita(Number(visitaItem.dataset.ts)); return; }
  const botTipoBtn = t.closest('[data-bot-tipo]');
  if (botTipoBtn) { _setBotiquinTipo(botTipoBtn.dataset.botTipo); return; }

  const tooltipBtn = t.closest('[data-tooltip]');
  if (tooltipBtn) { toggleTooltip(tooltipBtn.dataset.tooltip); return; }

  const photoCapture = t.closest('.btn-photo-capture[data-photo]');
  if (photoCapture) { triggerPhoto(photoCapture.dataset.photo); return; }

  const photoRemove = t.closest('.photo-remove[data-photo]');
  if (photoRemove) { removePhoto(photoRemove.dataset.photo); return; }

  if (t.closest('#btnSaveLog'))    { saveLog();        return; }
  if (t.closest('#btnSaveMnt'))       { saveMnt();          return; }
  const sanRegBtn = t.closest('[data-san-id]');
  if (sanRegBtn) { _sanPreFill(sanRegBtn.dataset.sanId); return; }
  const sanEditBtn = t.closest('.san-edit-btn[data-ts]');
  if (sanEditBtn) { editMnt(Number(sanEditBtn.dataset.ts)); return; }
  const sanDelBtn  = t.closest('.san-del-btn[data-ts]');
  if (sanDelBtn)  { deleteMnt(Number(sanDelBtn.dataset.ts)); return; }
  if (t.closest('#btnCancelEdit'))    { cancelEditLog();    return; }
  if (t.closest('#btnCancelEditMnt')) { cancelEditMnt();    return; }
  if (t.closest('#btnClearFilter')) { clearLogFilter(); return; }

  const afrTypeBtn = t.closest('[data-afr-type]');
  if (afrTypeBtn) { setAFRType(afrTypeBtn.dataset.afrType); return; }

  const momentoBtn = t.closest('.momento-btn[data-momento]');
  if (momentoBtn) { _setMomento(momentoBtn.dataset.momento); return; }

  const fisBtn = t.closest('.fis-btn[data-val]');
  if (fisBtn) {
    const group = fisBtn.closest('[data-fis-id]');
    if (group) {
      group.querySelectorAll('.fis-btn').forEach(b => b.classList.remove('active'));
      fisBtn.classList.add('active');
    }
    return;
  }

  if (t.closest('#afrPrev')) { afrStep(-1); return; }
  if (t.closest('#afrNext')) {
    const steps = AFR_STEPS[APP.afrType];
    if (APP.afrStep === steps.length - 1) finishAFR();
    else afrStep(1);
    return;
  }
  if (t.closest('#btnResetAFR')) { resetAFR(); return; }

  if (t.closest('#btnClearRepRange'))   { clearRepRange();  return; }
  if (t.closest('#btnRepMesActual'))    { setRepMes(0);    return; }
  if (t.closest('#btnRepMesAnterior'))  { setRepMes(-1);   return; }
  if (t.closest('#btnGeneratePDF'))     { generatePDF();       return; }
  if (t.closest('#btnExportCSV'))       { exportarCSVBitacora(); return; }
  if (t.closest('#btnExportJSON'))      { exportarBackupJSON();  return; }

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
  if (t.id === 'visitaDetailOverlay' || t.closest('#visitaDetailOverlay .log-detail-close')) {
    document.getElementById('visitaDetailOverlay')?.classList.add('js-hidden'); return;
  }

  if (t.closest('#preloaderBtn')) { preloaderNext(); return; }
  const dismissBtn = t.closest('[data-dismiss]');
  if (dismissBtn) { dismissPreloader(dismissBtn.dataset.dismiss); return; }

  if (t.closest('#jgFab'))          { openJGPanel();  return; }
  if (t.closest('#jgPanelClose'))   { closeJGPanel(); return; }
  if (t.closest('#jgPanelBackdrop')){ closeJGPanel(); return; }

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
       'logCloroComb','logBromo','logTurb','logTemp','logTempAire','logHumedad','logDureza','logOrp','logTds','logCond'].includes(id)) {
    checkLogForm(); return;
  }

  if (id === 'logBanistasMenores' || id === 'logBanistasMayores') {
    _updateBanistasTotal(); return;
  }

  if (['mntFecha','mntTecnico','mntDescripcion'].includes(id)) { checkMntForm(); return; }

  if (id === 'repNombre' || id === 'repResponsable' || id === 'repUbicacion' || id === 'repVolumen') {
    saveReportFields(); return;
  }

  if (id === 'fechaSalvavidas') { updateVencimientos(); return; }
  if (id === 'fechaBotiquin' || id === 'fechaDeaMant' || id === 'fechaDeaElectrodos') { _updateBotiquinDates(); return; }

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

  // Zonas Res. 234/2026: ideal -0.3 a +0.3 | aceptable -0.5 a +0.5
  // lsi=-0.5→1.25π | lsi=-0.3→1.35π | lsi=+0.3→1.65π | lsi=+0.5→1.75π
  const segments = [
    { start: Math.PI,        end: Math.PI * 1.25, color: '#dc2626' },
    { start: Math.PI * 1.25, end: Math.PI * 1.35, color: '#f59e0b' },
    { start: Math.PI * 1.35, end: Math.PI * 1.65, color: '#0cb86a' },
    { start: Math.PI * 1.65, end: Math.PI * 1.75, color: '#f59e0b' },
    { start: Math.PI * 1.75, end: Math.PI * 2,    color: '#dc2626' },
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
  ctx.fillStyle = '#dc2626';
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
  { id: 'g-alc',       key: 'alc',       label: 'Alcalinidad total',       unit: 'ppm',   min: 0,  max: 200,  range: 'Ideal: 80–120 · Máx. 150 ppm', normMin: 0,    normMax: 150,
    icon: '<path d="M2 12c1.5-2 3-2 4.5 0s3 2 4.5 0 3-2 4.5 0 3 2 4.5 0"/><path d="M2 17c1.5-2 3-2 4.5 0s3 2 4.5 0 3-2 4.5 0 3 2 4.5 0"/>' },
  { id: 'g-dureza',    key: 'dureza',    label: 'Dureza cálcica',          unit: 'ppm',   min: 0,  max: 800,  range: 'Ideal: 200–400 · Máx. 700 ppm', normMin: 200,  normMax: 700,
    icon: '<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>' },
  { id: 'g-cya',       key: 'cya',       label: 'Estabilizador (CYA)',     unit: 'ppm',   min: 0,  max: 20,   range: 'Máx. 15 ppm',         normMin: 0,    normMax: 15,
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
    ctx.fillStyle = !inRange ? '#dc2626' : isWarn ? '#f59e0b' : '#0cb86a';
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

function _renderDashEstablishment() {
  const el = document.getElementById('dashEstablishment');
  if (!el) return;
  const p = getPerfil();
  if (!p.razonSocial) { el.classList.add('js-hidden'); return; }
  const loc = [p.municipio, p.departamento].filter(Boolean).join(', ');
  el.innerHTML = `<span class="dash-est-icon">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
  </span><span class="dash-est-name">${escapeHtml(p.razonSocial)}</span>${loc ? `<span class="dash-est-loc"> · ${escapeHtml(loc)}</span>` : ''}${p.aforo ? `<span class="dash-est-loc"> · Aforo: ${p.aforo} bañistas</span>` : ''}`;
  el.classList.remove('js-hidden');
}

function renderDashboardIndices() {
  const el = document.getElementById('dashIndices');
  if (!el) return;

  if (!getLog().length) { el.innerHTML = ''; return; }

  const irapiResult = JSON.parse(sessionStorage.getItem('aqua_irapi_result') || 'null');
  const lastWithISL = getLog().find(e => e.isl != null);
  const lsiResult   = lastWithISL ? { lsi: lastWithISL.isl, status: lastWithISL.islStatus } : null;

  if (!irapiResult && !lsiResult) { el.innerHTML = ''; return; }

  const irapiCls = !irapiResult ? 'muted'
    : irapiResult.score <= 10 ? 'ok'
    : irapiResult.score <= 35 ? 'warn'
    : irapiResult.score <= 75 ? 'mid'
    : 'danger';

  const lsiCls = !lsiResult ? 'muted'
    : lsiResult.status === 'Equilibrada' ? 'ok'
    : lsiResult.status === 'Incrustante' ? 'warn'
    : 'danger';

  const irapiCard = irapiResult ? `
    <div class="dash-index-card${irapiCls === 'danger' ? ' dash-index-card--danger' : ''}">
      <div class="dash-index-top">
        <span class="dash-index-name">Riesgo sanitario (IRAPI)</span>
        <span class="dash-index-badge idx-badge-${irapiCls}">${irapiResult.label}</span>
      </div>
      <div class="dash-index-score c-${irapiCls}">${irapiResult.score}</div>
      <div class="dash-index-bar-bg">
        <div class="dash-index-bar-fill idx-bar-${irapiCls}" data-pct="${Math.min(irapiResult.score,100)}"></div>
      </div>
      <div class="dash-index-hint">Escala 0–100</div>
    </div>` : '';

  const lsiCard = lsiResult ? `
    <div class="dash-index-card">
      <div class="dash-index-top">
        <span class="dash-index-name">Equilibrio del agua (ISL)</span>
        <span class="dash-index-badge idx-badge-${lsiCls}">${lsiResult.status}</span>
      </div>
      <div class="dash-index-score c-${lsiCls}">${lsiResult.lsi.toFixed(2)}</div>
      <div class="dash-index-bar-bg">
        <div class="dash-index-bar-fill idx-bar-${lsiCls}" data-pct="${Math.min(Math.abs(lsiResult.lsi)/2*100,100)}"></div>
      </div>
      <div class="dash-index-hint">Ideal: −0.3 a +0.3 · Aceptable: −0.5 a +0.5</div>
    </div>` : '';

  el.innerHTML = `<div class="dash-indices-grid">${irapiCard}${lsiCard}</div>`;
  el.querySelectorAll('.dash-index-bar-fill[data-pct]').forEach(bar => {
    bar.style.width = bar.dataset.pct + '%';
  });
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

  // Concepto sanitario — lee de la última visita registrada
  const ultimaVisita = _visitasRaw()[0];
  if (ultimaVisita) {
    if (ultimaVisita.concepto === 'desfavorable') alerts.push({ label: 'Concepto sanitario', msg: 'Desfavorable', cls: 'venc-danger' });
    else if (ultimaVisita.concepto === 'requerimientos') alerts.push({ label: 'Concepto sanitario', msg: 'Con requerimientos', cls: 'venc-warning' });
    if (ultimaVisita.plazo) {
      const plazoD = Math.ceil((new Date(ultimaVisita.plazo + 'T00:00:00') - new Date()) / 86400000);
      if (plazoD < 0)       alerts.push({ label: 'Plazo sanitario', msg: 'VENCIDO',           cls: 'venc-danger'  });
      else if (plazoD <= 7) alerts.push({ label: 'Plazo sanitario', msg: `Vence en ${plazoD}d`, cls: 'venc-warning' });
    }
  } else {
    const concepto = dates['concepto'];
    if (concepto === 'rojo')         alerts.push({ label: 'Concepto sanitario', msg: 'Desfavorable',          cls: 'venc-danger'  });
    else if (concepto === 'amarillo') alerts.push({ label: 'Concepto sanitario', msg: 'Con requerimientos', cls: 'venc-warning' });
  }

  // Saneamiento básico
  const mntRaw = _mntLogRaw();
  SANEAMIENTO_PROGRAMS.forEach(prog => {
    const shortLabel = (MNT_AREA_LABELS[prog.id] || { label: prog.label }).label;
    const last = mntRaw.find(e => e.area === prog.id);
    if (!last) {
      alerts.push({ label: shortLabel, msg: 'Sin registro', cls: 'venc-warning' });
      return;
    }
    const ds = Math.floor((Date.now() - new Date(last.fecha + 'T00:00:00')) / 86400000);
    if (ds > prog.dias) alerts.push({ label: shortLabel, msg: 'VENCIDO', cls: 'venc-danger' });
    else if (ds > prog.dias - Math.ceil(prog.dias * 0.3)) alerts.push({ label: shortLabel, msg: `Vence en ${prog.dias - ds}d`, cls: 'venc-warning' });
  });

  // Botiquín
  const botData = getBotiquin();
  if (botData.fechaVerificacion) {
    const botDays = Math.floor((Date.now() - new Date(botData.fechaVerificacion + 'T00:00:00')) / 86400000);
    if (botDays > 30) alerts.push({ label: 'Botiquín', msg: `Hace ${botDays}d`, cls: 'venc-danger' });
    else if (botDays > 20) alerts.push({ label: 'Botiquín', msg: `Hace ${botDays}d`, cls: 'venc-warning' });
  } else {
    alerts.push({ label: 'Botiquín', msg: 'Sin verificar', cls: 'venc-warning' });
  }
  if (botData.tipo === 'C' && botData.fechaDeaElectrodos) {
    const deaDays = Math.ceil((new Date(botData.fechaDeaElectrodos + 'T00:00:00') - new Date()) / 86400000);
    if (deaDays < 0)       alerts.push({ label: 'DEA electrodos', msg: 'VENCIDO',          cls: 'venc-danger'  });
    else if (deaDays <= 30) alerts.push({ label: 'DEA electrodos', msg: `Vence en ${deaDays}d`, cls: 'venc-warning' });
  }

  // Aptitud del estanque
  const todayStr   = localDateStr(new Date());
  const todayEntry = _logRaw().find(e => e.fecha === todayStr);
  if (todayEntry && todayEntry.aptitud === 'no_apta') {
    alerts.push({ label: 'Estanque', msg: 'No apta para el servicio', cls: 'venc-danger' });
  }

  // Seguridad diaria
  if (todayEntry) {
    const segN = _segCount(todayEntry.seguridad);
    if (segN < 0) alerts.push({ label: 'Seguridad diaria', msg: 'Sin verificar hoy', cls: 'venc-warning' });
    else if (segN < SEG_ITEMS.length) alerts.push({ label: 'Seguridad diaria', msg: `${segN}/${SEG_ITEMS.length} verificados`, cls: 'venc-warning' });
  }

  // Análisis de laboratorio trimestral
  const labRecords   = getLabRecords();
  const labDaysSince = _labDaysSince(labRecords[0] || null);
  if (labDaysSince === null) {
    alerts.push({ label: 'Lab. trimestral', msg: 'Sin registro', cls: 'venc-warning' });
  } else if (labDaysSince > 90) {
    alerts.push({ label: 'Lab. trimestral', msg: 'VENCIDO', cls: 'venc-danger' });
  } else if (labDaysSince > 75) {
    alerts.push({ label: 'Lab. trimestral', msg: `Vence en ${90 - labDaysSince}d`, cls: 'venc-warning' });
  }

  if (!alerts.length) { el.style.display = 'none'; return; }

  el.style.display = 'block';
  el.innerHTML = `
    <div class="dash-venc-wrap">
      <div class="dash-venc-header">
        <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <strong>Documentos con vencimiento próximo</strong>
        <button class="btn btn-sm btn-outline js-go-venc dash-venc-btn">Ver vencimientos</button>
      </div>
      ${alerts.map(({ label, msg, cls }) =>
        `<div class="dash-venc-item ${cls}"><span>${label}</span><span class="venc-badge">${msg}</span></div>`
      ).join('')}
    </div>
  `;
}

function updateNavVencBadge() {
  const badge = document.getElementById('navVencBadge');
  if (!badge) return;

  const profile = getDocsProfile();
  let count = 0;

  if (profile === 'publico') {
    const dates = JSON.parse(localStorage.getItem('aqua_docs_dates') || '{}');
    const val = dates['fechaSalvavidas'];
    if (val) {
      const days = Math.ceil((new Date(val + 'T00:00:00') - new Date()) / 86400000);
      if (days <= 30) count++;
    }
    const ultimaVisita = _visitasRaw()[0];
    if (ultimaVisita) {
      if (ultimaVisita.concepto === 'desfavorable' || ultimaVisita.concepto === 'requerimientos') count++;
      if (ultimaVisita.plazo) {
        const plazoD = Math.ceil((new Date(ultimaVisita.plazo + 'T00:00:00') - new Date()) / 86400000);
        if (plazoD <= 7) count++;
      }
    }
    const mntRaw = _mntLogRaw();
    SANEAMIENTO_PROGRAMS.forEach(prog => {
      const last = mntRaw.find(e => e.area === prog.id);
      if (!last) return;
      const ds = Math.floor((Date.now() - new Date(last.fecha + 'T00:00:00')) / 86400000);
      if (ds > prog.dias - Math.ceil(prog.dias * 0.3)) count++;
    });
    const botData = getBotiquin();
    if (botData.fechaVerificacion) {
      const botDays = Math.floor((Date.now() - new Date(botData.fechaVerificacion + 'T00:00:00')) / 86400000);
      if (botDays > 20) count++;
    }
    const labRecords = getLabRecords();
    const labDaysSince = _labDaysSince(labRecords[0] || null);
    if (labDaysSince !== null && labDaysSince > 75) count++;
  }

  if (count === 0) { badge.classList.add('js-hidden'); badge.textContent = ''; return; }
  badge.classList.remove('js-hidden');
  badge.textContent = count;
}

function renderDashMntSchedule() {
  const el = document.getElementById('dashMntSchedule');
  if (!el) return;

  const today = new Date(); today.setHours(0, 0, 0, 0);
  const pending = _mntLogRaw()
    .filter(e => e.proximo)
    .map(e => {
      const d = new Date(e.proximo + 'T00:00:00');
      return { label: (MNT_AREA_LABELS[e.area] || { label: e.area }).label, date: d,
               days: Math.ceil((d - today) / 86400000) };
    })
    .sort((a, b) => a.days - b.days)
    .slice(0, 4);

  if (!pending.length) { el.classList.add('js-hidden'); return; }

  const rows = pending.map(({ label, days }) => {
    const cls  = days < 0 ? 'mnt-sch-danger' : days <= 7 ? 'mnt-sch-warning' : 'mnt-sch-ok';
    const msg  = days < 0 ? `Vencida hace ${Math.abs(days)}d` : days === 0 ? 'Hoy' : `En ${days} día${days === 1 ? '' : 's'}`;
    return `<div class="mnt-sch-item ${cls}"><span class="mnt-sch-label">${label}</span><span class="mnt-sch-badge">${msg}</span></div>`;
  }).join('');

  el.innerHTML = `
    <div class="mnt-sch-wrap">
      <div class="mnt-sch-header">
        <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
        <strong>Próximas revisiones de mantenimiento</strong>
        <button class="btn btn-sm btn-outline dash-venc-btn" data-navigate="mantenimiento">Ver todo</button>
      </div>
      ${rows}
    </div>
  `;
  el.classList.remove('js-hidden');
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
    const colorCls = value === null ? 'c-muted' : !cumple ? 'c-danger' : warn ? 'c-warn' : 'c-ok';
    const display  = value !== null ? value : '–';

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
      <div class="gauge-val ${colorCls}">
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
      drawGauge(p.id, value, p.min, p.max, !cumple ? '#dc2626' : warn ? '#f59e0b' : '#0cb86a');
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
    '🏊 Aqua Tech — Estado de piscina',
    `📅 ${fecha}${hora}${op}`,
    '',
    `${stateEmoji} ${stateLabel}`,
    normLabel,
    '',
    'Parámetros:',
    ...paramLines,
    irapiLine,
    '',
    '— Generado con Aqua Tech',
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
    navigator.share({ title: 'Estado de piscina — Aqua Tech', text })
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
  alcalinidad: { label: 'Alcalinidad total',    unit: 'ppm', range: 'Ideal: 80–120 · Máx. 150 ppm', min: 0,  max: 200, normMin: 0,   normMax: 150,  doseLabel: 'DOSIS RECOMENDADA · BICARBONATO DE SODIO',        doseUnit: 'g', note: 'Disolver antes de agregar. Reevaluar en 4–6 horas.' },
  cya:         { label: 'Estabilizador de cloro (CYA)', unit: 'ppm',range: 'Máx. 15 ppm',    min: 0, max: 20,  normMin: 0,   normMax: 15,   doseLabel: 'NIVEL DE ESTABILIZADOR (CYA)',                     doseUnit: 'ppm', note: 'Si supera 15 ppm, reemplazar parte del agua sin estabilizador.' },
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
      <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#92400e" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
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
      body = `<div class="calc-noaction calc-noaction-warn"><svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#92400e" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
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
  const AMIN = 0,   AMAX = 150,  CYAMAX = 15;

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

  // Res. 234/2026 Anexo I: ideal -0.3 a +0.3 | aceptable -0.5 a +0.5
  if (lsi < -0.5) {
    status = 'Corrosiva'; color = '#dc2626';
    legend[0]?.classList.add('active-leg');
  } else if (lsi < -0.3) {
    status = 'Tendencia corrosiva'; color = '#f59e0b';
    legend[0]?.classList.add('active-leg');
  } else if (lsi > 0.5) {
    status = 'Incrustante'; color = '#dc2626';
    legend[2]?.classList.add('active-leg');
  } else if (lsi > 0.3) {
    status = 'Tendencia incrustante'; color = '#f59e0b';
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
  _setLsiPBadge('lsiAlkBadge',  alk <= 150,                    '✓', '✗ fuera');

  // ── Diagnóstico completo ──────────────────────────────
  const diagEl = document.getElementById('lsiDiagnosis');
  if (diagEl) {
    const phOk   = pH >= 6.8 && pH <= 7.3;
    const hardOk = hard >= 200 && hard <= 700;
    const alkOk  = alk <= 150;
    const tempOk = temp <= 40;
    const allOk  = phOk && hardOk && alkOk && tempOk;

    if (lsi < -0.5) {
      // ── Corrosiva ──
      const tips = [];
      if (pH < 6.8)   tips.push(`Subir pH — actual ${pH}, mínimo 6.8`);
      if (hard < 200) tips.push(`Subir dureza cálcica — actual ${hard} ppm, mínimo 200 ppm`);
      if (alk < 80)   tips.push(`Subir alcalinidad — actual ${alk} ppm, rango ideal 80–120 ppm (máx. 150 ppm)`);
      if (!tips.length) tips.push('Combinación de factores genera índice negativo. Revisar pH y alcalinidad.');
      diagEl.innerHTML = `<div class="lsi-diag-box lsi-box-danger">
        <div class="lsi-diag-title lsi-title-danger">
          <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          Agua corrosiva — puede dañar superficies, tuberías y equipos
        </div>
        <ul class="lsi-diag-list">${tips.map(t => `<li>${t}</li>`).join('')}</ul>
      </div>`;

    } else if (lsi >= -0.5 && lsi < -0.3) {
      // ── Tendencia corrosiva (aceptable pero fuera del ideal) ──
      const tips = [];
      if (pH < 6.8)   tips.push(`Subir pH — actual ${pH}, mínimo 6.8`);
      if (hard < 200) tips.push(`Subir dureza cálcica — actual ${hard} ppm, mínimo 200 ppm`);
      if (alk < 80)   tips.push(`Subir alcalinidad al rango ideal (80–120 ppm)`);
      if (!tips.length) tips.push('Ajustar parámetros hacia el rango ideal −0.3 a +0.3.');
      diagEl.innerHTML = `<div class="lsi-diag-box lsi-box-warn">
        <div class="lsi-diag-title lsi-title-warn">
          <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          Tendencia corrosiva — ISL aceptable pero fuera del rango ideal (−0.3 a +0.3)
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
      diagEl.innerHTML = `<div class="lsi-diag-box lsi-box-danger">
        <div class="lsi-diag-title lsi-title-danger">
          <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          Agua incrustante — puede formar sarro en tuberías y equipos
        </div>
        <ul class="lsi-diag-list">${tips.map(t => `<li>${t}</li>`).join('')}</ul>
      </div>`;

    } else if (lsi > 0.3) {
      // ── Tendencia incrustante (aceptable pero fuera del ideal) ──
      const tips = [];
      if (pH > 7.3)   tips.push(`Bajar pH — actual ${pH}, máximo 7.3`);
      if (alk > 150)  tips.push(`Bajar alcalinidad — actual ${alk} ppm, máximo 150 ppm`);
      if (hard > 700) tips.push(`Dureza cálcica alta — actual ${hard} ppm, ideal hasta 400 ppm`);
      if (!tips.length) tips.push('Ajustar parámetros hacia el rango ideal −0.3 a +0.3.');
      diagEl.innerHTML = `<div class="lsi-diag-box lsi-box-warn">
        <div class="lsi-diag-title lsi-title-warn">
          <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          Tendencia incrustante — ISL aceptable pero fuera del rango ideal (−0.3 a +0.3)
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
      if (alk > 150)  { elevando.push(`Alcalinidad alta (${alk} ppm) eleva el ISL`); corregir.push(`Bajar alcalinidad — máx. 150 ppm`); }
      if (alk < 80)   { reduciendo.push(`Alcalinidad baja (${alk} ppm) reduce el ISL`); corregir.push(`Subir alcalinidad al rango ideal (80–120 ppm)`); }
      if (temp > 40)  { elevando.push(`Temperatura alta (${temp} °C) eleva el ISL`); corregir.push(`Temperatura excede el máximo de 40 °C`); }

      const efectos = [...elevando, ...reduciendo];
      diagEl.innerHTML = `<div class="lsi-diag-box lsi-box-amber">
        <div class="lsi-diag-title lsi-title-amber">
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
      const wHtml = `<div class="lsi-diag-box lsi-box-danger-mb">
        <div class="lsi-diag-title lsi-title-danger">
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
  if (score > 75)      { label = 'Alto';  color = '#dc2626'; cls = 'alto'; }
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
    { key: 'micro', val: micro * 0.45, raw: micro },
    { key: 'alk',   val: alk   * 0.30, raw: alk   },
    { key: 'cloro', val: cloro * 0.20, raw: cloro },
    { key: 'otros', val: otros * 0.05, raw: otros  },
  ];
  const dominant = contributions.reduce((a, b) =>
    b.val > a.val ? b : (b.val === a.val && b.raw > a.raw ? b : a)
  ).key;
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
    (e.cya  != null && !isNaN(e.cya)  && e.cya  > 15)
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

function calcHorasFun() {
  const ini = document.getElementById('logHoraInicio')?.value;
  const fin = document.getElementById('logHoraFin')?.value;
  if (!ini || !fin) return;
  const [hI, mI] = ini.split(':').map(Number);
  const [hF, mF] = fin.split(':').map(Number);
  let mins = (hF * 60 + mF) - (hI * 60 + mI);
  if (mins <= 0) return;
  const horas = +(mins / 60).toFixed(1);
  const el = document.getElementById('logHorasFun');
  if (el && !el.value) el.value = horas;
}

function updateCaudalLpm() {
  const el   = document.getElementById('logCaudal');
  const hint = document.getElementById('caudalLpmHint');
  if (!el || !hint) return;
  const v = parseFloat(el.value);
  hint.textContent = isNaN(v) || v <= 0 ? '' : `≈ ${Math.round(v * 1000 / 60)} lpm`;
}

function updateSalvavidasDatalist() {
  const dl = document.getElementById('salvavidasList');
  if (!dl) return;
  const fromPerfil = (getPerfil().salvavidas || []).filter(s => s.nombre);
  const fromHistory = [...new Set(
    _logRaw().map(e => e.salvavidas).filter(n => n && n.trim())
  )];
  const combined = [...new Set([...fromPerfil.map(s => s.nombre), ...fromHistory])].sort();
  dl.innerHTML = combined.map(n => `<option value="${escapeHtml(n)}"></option>`).join('');
}

function onSalvavidasInput() {
  const name = document.getElementById('logSalvavidas')?.value.trim();
  if (!name) return;
  const match = (getPerfil().salvavidas || []).find(s => s.nombre.trim() === name);
  if (match && match.nia) {
    const niaEl = document.getElementById('logSalvavidasNia');
    if (niaEl && !niaEl.value) niaEl.value = match.nia;
  }
}

// ── LABORES DIARIAS ───────────────────────────────────────
const LAB_ITEMS = [
  { id: 'flotante',      label: 'Material flotante' },
  { id: 'paredesRompe',  label: 'Paredes y rompebolas' },
  { id: 'fondo',         label: 'Aspirado del fondo' },
  { id: 'desnatadores',  label: 'Desnatadores' },
  { id: 'duchasLavapies',label: 'Duchas preimmersión y lavapies' },
  { id: 'andenes',       label: 'Andenes perimetrales' },
];

function _labCount(lab) {
  if (!lab || typeof lab !== 'object') return -1;
  return LAB_ITEMS.filter(i => lab[i.id]).length;
}

function updateLabCounter() {
  const checked = LAB_ITEMS.filter(i => document.getElementById('lab_' + i.id)?.checked).length;
  const el = document.getElementById('labCounter');
  if (!el) return;
  el.textContent = `${checked} / ${LAB_ITEMS.length}`;
  el.className = 'seg-counter' + (checked === LAB_ITEMS.length ? ' seg-counter-ok' : checked > 0 ? ' seg-counter-partial' : '');
}

// ── SEGURIDAD DIARIA ──────────────────────────────────────
const SEG_ITEMS = [
  { id: 'cierrePer', label: 'Cierre perimetral' },
  { id: 'alarmaPer', label: 'Alarma perimetral' },
  { id: 'svr',       label: 'Sistema de liberación de vacío (SVR)' },
  { id: 'alarmaIm',  label: 'Alarma de inmersión' },
  { id: 'btnParo',   label: 'Botón de parada de emergencia' },
  { id: 'rejilla',   label: 'Rejilla antiatrapamiento' },
  { id: 'tapones',   label: 'Tapones de succión de pared' },
];

function _segCount(seg) {
  if (!seg || typeof seg !== 'object') return -1;
  return SEG_ITEMS.filter(i => seg[i.id]).length;
}

function updateSegCounter() {
  const checked = SEG_ITEMS.filter(i => document.getElementById('seg_' + i.id)?.checked).length;
  const el = document.getElementById('segCounter');
  if (!el) return;
  el.textContent = `${checked} / ${SEG_ITEMS.length}`;
  el.className = 'seg-counter' + (checked === SEG_ITEMS.length ? ' seg-counter-ok' : checked > 0 ? ' seg-counter-partial' : '');
}

// ── INSTALACIÓN — ALISTAMIENTO 7 ─────────────────────────
const INST_ITEMS = [
  { id: 'lavapies',  label: 'Lavapies y duchas preimmersión' },
  { id: 'estanque',  label: 'Estanque (revestimiento)' },
  { id: 'pedaneos',  label: 'Pedaneos, escaleras y pasamanos' },
  { id: 'tapas',     label: 'Tapas desnatadoras' },
  { id: 'rejillas',  label: 'Rejillas desnatadoras' },
];

function _instCount(inst) {
  if (!inst || typeof inst !== 'object') return -1;
  return INST_ITEMS.filter(i => inst[i.id]).length;
}

function updateInstCounter() {
  const checked = INST_ITEMS.filter(i => document.getElementById('inst_' + i.id)?.checked).length;
  const el = document.getElementById('instCounter');
  if (!el) return;
  el.textContent = `${checked} / ${INST_ITEMS.length}`;
  el.className = 'seg-counter' + (checked === INST_ITEMS.length ? ' seg-counter-ok' : checked > 0 ? ' seg-counter-partial' : '');
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
    && ['solido', 'vomito', 'diarreico', 'sangre', 'quimicos'].includes(e.tipo)
    && typeof e.fecha === 'string' && e.fecha.length > 0;
}

function _logRaw() {
  try {
    const raw = JSON.parse(localStorage.getItem('aqua_bitacora') || '[]');
    return Array.isArray(raw) ? raw.filter(_isValidLogEntry) : [];
  } catch { return []; }
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
let editingLogTs   = null;
let editingMntTs   = null;
let _momentoActual = 'apertura';
let _newLogTs    = 0;
let _trendParam  = 'cloro';
let _trendDays   = 7;

// Rangos Res. 234/2026 para cada campo de bitácora
const LOG_PARAM_RANGES = [
  { id: 'logCloro',     badge: 'logCloroBadge',     min: 2.0, max: 4.0  },
  { id: 'logCloroComb', badge: 'logCloroCombBadge', min: 0,   max: 0.3  },
  { id: 'logBromo',     badge: 'logBromoBadge',     min: 2.0, max: 4.0  },
  { id: 'logPh',        badge: 'logPhBadge',        min: 6.8, max: 7.3  },
  { id: 'logAlc',       badge: 'logAlcBadge',       min: 0,   max: 150  },
  { id: 'logDureza',   badge: 'logDurezaBadge',    min: 200, max: 700  },
  { id: 'logCya',       badge: 'logCyaBadge',       min: 0,   max: 15   },
  { id: 'logTurb',      badge: 'logTurbBadge',      min: 0,   max: 0.5  },
  { id: 'logTemp',      badge: 'logTempBadge',      min: 0,   max: 40   },
  { id: 'logHumedad',  badge: 'logHumedadBadge',   min: 40,  max: 60   },
  { id: 'logOrp',        badge: 'logOrpBadge',        min: 0,    max: 700, warnBelow: 650 },
  { id: 'logTds',        badge: 'logTdsBadge',        min: 1000, max: 1200 },
  { id: 'logCond',       badge: 'logCondBadge',       min: 2000, max: 2400 },
  { id: 'logNivelAgua',  badge: 'logNivelAguaBadge',  min: 0,    max: 0.6  },
];

function onAptitudChange() {
  const noApta = document.getElementById('apt_no_apta')?.checked;
  const wrap   = document.getElementById('aptRazonWrap');
  if (wrap) wrap.hidden = !noApta;
  const sug = document.getElementById('aptSuggestion');
  if (sug) sug.textContent = '';
  document.getElementById('aptLabelApta')?.classList.toggle('apt-selected', !noApta && !!document.getElementById('apt_apta')?.checked);
  document.getElementById('aptLabelNoApta')?.classList.toggle('apt-selected', !!noApta);
}

function _updateAptitudSuggestion(outRange, filled) {
  const sug = document.getElementById('aptSuggestion');
  if (!sug) return;
  const anySelected = document.getElementById('apt_apta')?.checked || document.getElementById('apt_no_apta')?.checked;
  if (anySelected || filled === 0) { sug.textContent = ''; return; }
  if (outRange === 0) {
    sug.className = 'apt-suggestion apt-sug-ok';
    sug.textContent = '✓ Todos los parámetros en rango — se sugiere: Apta';
  } else {
    sug.className = 'apt-suggestion apt-sug-warn';
    sug.textContent = `⚠ ${outRange} parámetro${outRange > 1 ? 's' : ''} fuera de rango — se sugiere: No apta`;
  }
}

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
  if (filled === 0) { bar.style.display = 'none'; _updateAptitudSuggestion(0, 0); return; }
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
  _updateAptitudSuggestion(outRange, filled);
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

function _updateBanistasTotal() {
  const m = parseInt(document.getElementById('logBanistasMenores')?.value) || 0;
  const M = parseInt(document.getElementById('logBanistasMayores')?.value) || 0;
  const totalEl = document.getElementById('banistasTotal');
  if (!totalEl) return;
  const hasMenores = document.getElementById('logBanistasMenores')?.value !== '';
  const hasMayores = document.getElementById('logBanistasMayores')?.value !== '';
  totalEl.textContent = (hasMenores || hasMayores) ? (m + M) : '–';
}

function _setMomento(val) {
  _momentoActual = val;
  document.querySelectorAll('.momento-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.momento === val);
  });
}

function _getFisVal(id) {
  return document.querySelector(`[data-fis-id="${id}"] .fis-btn.active`)?.dataset.val || null;
}
function _setFisVal(id, val) {
  if (!val) return;
  document.querySelectorAll(`[data-fis-id="${id}"] .fis-btn`).forEach(b => {
    b.classList.toggle('active', b.dataset.val === val);
  });
}
function _resetFis() {
  _setFisVal('fisColor',    'aceptable');
  _setFisVal('fisFlotantes','ausentes');
  _setFisVal('fisOlor',     'aceptable');
  _setFisVal('fisTransp',   'visible');
}
function _fisTodosOk(entry) {
  return (entry.fisColor     || 'aceptable')    === 'aceptable'
      && (entry.fisFlotantes || 'ausentes')      === 'ausentes'
      && (entry.fisOlor      || 'aceptable')     === 'aceptable'
      && (entry.fisTransp    || 'visible')       === 'visible';
}
const _FIS_LABELS = {
  aceptable:    'Aceptable',
  'no-aceptable': 'No aceptable',
  ausentes:     'Ausentes',
  presentes:    'Presentes',
  visible:      'Fondo visible',
  'no-visible': 'No visible',
};

function clearLogForm() {
  const now  = new Date();
  document.getElementById('logDate').value      = localDateStr(now);
  document.getElementById('logTime').value      = now.toTimeString().slice(0, 5);
  document.getElementById('logOperador').value     = getPerfil().opNombre || '';
  document.getElementById('logSalvavidas').value   = '';
  document.getElementById('logSalvavidasNia').value= '';
  document.getElementById('logCloro').value        = '';
  document.getElementById('logCloroComb').value = '';
  document.getElementById('logBromo').value     = '';
  document.getElementById('logPh').value        = '';
  document.getElementById('logAlc').value       = '';
  document.getElementById('logCya').value       = '';
  document.getElementById('logTurb').value      = '';
  document.getElementById('logTemp').value      = '';
  document.getElementById('logTempAire').value  = '';
  document.getElementById('logHumedad').value   = '';
  document.getElementById('logDureza').value    = '';
  document.getElementById('logBanistasMenores').value = '';
  document.getElementById('logBanistasMayores').value = '';
  _updateBanistasTotal();
  document.getElementById('logOrp').value       = '';
  document.getElementById('logTds').value       = '';
  document.getElementById('logCond').value      = '';
  document.getElementById('logCaudal').value    = '';
  document.getElementById('logHorasFun').value  = '';
  document.getElementById('logHorasFilt').value = '';
  document.getElementById('logAguaRep').value   = '';
  document.getElementById('logRetrolav').value   = '';
  document.getElementById('logPresion').value    = '';
  document.getElementById('logNivelAgua').value  = '';
  document.getElementById('logHoraInicio').value    = '';
  document.getElementById('logHoraFin').value       = '';
  document.getElementById('logNeutralizador').value = '';
  document.getElementById('logCloroDos').value      = '';
  document.getElementById('logHoraAjuste').value    = '';
  document.getElementById('logProdQuim').value  = '';
  document.getElementById('logAverias').value   = '';
  document.getElementById('logNotas').value     = '';
  _applyPhoto('fotoAgua',   null);
  _applyPhoto('fotoAveria', null);
  _setMomento('apertura');
  _resetFis();
  LAB_ITEMS.forEach(i => { const el = document.getElementById('lab_' + i.id); if (el) el.checked = false; });
  updateLabCounter();
  SEG_ITEMS.forEach(i  => { const el = document.getElementById('seg_'  + i.id); if (el) el.checked = false; });
  updateSegCounter();
  INST_ITEMS.forEach(i => { const el = document.getElementById('inst_' + i.id); if (el) el.checked = false; });
  updateInstCounter();
  const aptApta   = document.getElementById('apt_apta');
  const aptNoApta = document.getElementById('apt_no_apta');
  if (aptApta)   aptApta.checked   = false;
  if (aptNoApta) aptNoApta.checked = false;
  document.getElementById('aptLabelApta')?.classList.remove('apt-selected');
  document.getElementById('aptLabelNoApta')?.classList.remove('apt-selected');
  const aptRazonWrap = document.getElementById('aptRazonWrap');
  if (aptRazonWrap) aptRazonWrap.hidden = true;
  const aptRazon = document.getElementById('aptRazon');
  if (aptRazon) aptRazon.value = '';
  const aptSug = document.getElementById('aptSuggestion');
  if (aptSug) aptSug.textContent = '';
  checkLogForm();
}

function editLog(ts) {
  const entry = getLog().find(e => e.ts === ts);
  if (!entry) return;
  editingLogTs = ts;
  document.getElementById('logDate').value      = entry.fecha     || '';
  document.getElementById('logTime').value      = entry.hora      || '';
  document.getElementById('logOperador').value     = entry.operador     || '';
  document.getElementById('logSalvavidas').value   = entry.salvavidas   || '';
  document.getElementById('logSalvavidasNia').value= entry.salvavidasNia|| '';
  document.getElementById('logCloro').value        = entry.cloro        ?? '';
  document.getElementById('logCloroComb').value = entry.clorocomb ?? '';
  document.getElementById('logBromo').value     = entry.bromo     ?? '';
  document.getElementById('logPh').value        = entry.ph        ?? '';
  document.getElementById('logAlc').value       = entry.alc       ?? '';
  document.getElementById('logCya').value       = entry.cya       ?? '';
  document.getElementById('logTurb').value      = entry.turb      ?? '';
  document.getElementById('logTemp').value      = entry.temp      ?? '';
  document.getElementById('logTempAire').value  = entry.tempAire  ?? '';
  document.getElementById('logHumedad').value   = entry.humedad   ?? '';
  document.getElementById('logDureza').value    = entry.dureza    ?? '';
  document.getElementById('logBanistasMenores').value = entry.banistasMenores ?? '';
  document.getElementById('logBanistasMayores').value = entry.banistasMayores ?? (entry.banistasMenores == null && entry.banistas != null ? entry.banistas : '');
  _updateBanistasTotal();
  document.getElementById('logOrp').value       = entry.orp       ?? '';
  document.getElementById('logTds').value       = entry.tds       ?? '';
  document.getElementById('logCond').value      = entry.cond      ?? '';
  document.getElementById('logCaudal').value    = entry.caudal    ?? '';
  updateCaudalLpm();
  document.getElementById('logHorasFun').value  = entry.horasFun  ?? '';
  document.getElementById('logHorasFilt').value = entry.horasFilt ?? '';
  document.getElementById('logAguaRep').value   = entry.aguaRep   ?? '';
  document.getElementById('logRetrolav').value   = entry.retrolav   ?? '';
  document.getElementById('logPresion').value    = entry.presion    ?? '';
  document.getElementById('logNivelAgua').value  = entry.nivelAgua  ?? '';
  document.getElementById('logHoraInicio').value    = entry.horaInicio    || '';
  document.getElementById('logHoraFin').value       = entry.horaFin       || '';
  document.getElementById('logNeutralizador').value = entry.neutralizador ?? '';
  document.getElementById('logCloroDos').value      = entry.cloroDos      ?? '';
  document.getElementById('logHoraAjuste').value    = entry.horaAjuste    || '';
  document.getElementById('logProdQuim').value  = entry.prodQuim  || '';
  document.getElementById('logAverias').value   = entry.averias   || '';
  document.getElementById('logNotas').value     = entry.notas     || '';
  _applyPhoto('fotoAgua',   entry.fotoAgua   || null);
  _applyPhoto('fotoAveria', entry.fotoAveria || null);
  _setMomento(entry.momento || 'apertura');
  _setFisVal('fisColor',     entry.fisColor     || 'aceptable');
  _setFisVal('fisFlotantes', entry.fisFlotantes || 'ausentes');
  _setFisVal('fisOlor',      entry.fisOlor      || 'aceptable');
  _setFisVal('fisTransp',    entry.fisTransp    || 'visible');
  LAB_ITEMS.forEach(i => { const el = document.getElementById('lab_' + i.id); if (el) el.checked = !!(entry.labores && entry.labores[i.id]); });
  updateLabCounter();
  SEG_ITEMS.forEach(i  => { const el = document.getElementById('seg_'  + i.id); if (el) el.checked = !!(entry.seguridad   && entry.seguridad[i.id]);   });
  updateSegCounter();
  INST_ITEMS.forEach(i => { const el = document.getElementById('inst_' + i.id); if (el) el.checked = !!(entry.instalacion && entry.instalacion[i.id]); });
  updateInstCounter();
  const aptEl = document.getElementById(entry.aptitud === 'no_apta' ? 'apt_no_apta' : entry.aptitud === 'apta' ? 'apt_apta' : '');
  if (aptEl) { aptEl.checked = true; onAptitudChange(); }
  const aptRazonEl = document.getElementById('aptRazon');
  if (aptRazonEl) aptRazonEl.value = entry.aptitudRazon || '';
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
  const banistasMenoresRaw = parseInt(document.getElementById('logBanistasMenores').value);
  const banistasMayoresRaw = parseInt(document.getElementById('logBanistasMayores').value);
  const banistasRaw = (!isNaN(banistasMenoresRaw) || !isNaN(banistasMayoresRaw))
    ? (isNaN(banistasMenoresRaw) ? 0 : banistasMenoresRaw) + (isNaN(banistasMayoresRaw) ? 0 : banistasMayoresRaw)
    : NaN;
  const orpRaw      = parseFloat(document.getElementById('logOrp').value);
  const tdsRaw      = parseFloat(document.getElementById('logTds').value);
  const condRaw     = parseFloat(document.getElementById('logCond').value);
  const caudalRaw   = parseFloat(document.getElementById('logCaudal').value);
  const horasFunRaw  = parseFloat(document.getElementById('logHorasFun').value);
  const horasFiltRaw = parseFloat(document.getElementById('logHorasFilt').value);
  const aguaRepRaw  = parseFloat(document.getElementById('logAguaRep').value);
  const retrolavRaw = parseInt(document.getElementById('logRetrolav').value);
  const presionRaw  = parseFloat(document.getElementById('logPresion').value);
  const durezaRaw   = parseFloat(document.getElementById('logDureza').value);
  const cyaRaw      = parseFloat(document.getElementById('logCya').value);
  return {
    fecha:      document.getElementById('logDate').value,
    hora:       document.getElementById('logTime').value,
    momento:    _momentoActual,
    fisColor:    _getFisVal('fisColor'),
    fisFlotantes:_getFisVal('fisFlotantes'),
    fisOlor:     _getFisVal('fisOlor'),
    fisTransp:   _getFisVal('fisTransp'),
    operador:      document.getElementById('logOperador').value,
    salvavidas:    document.getElementById('logSalvavidas').value.trim(),
    salvavidasNia: document.getElementById('logSalvavidasNia').value.trim(),
    cloro:      parseFloat(document.getElementById('logCloro').value),
    clorocomb:  parseFloat(document.getElementById('logCloroComb').value),
    bromo:      (() => { const v = parseFloat(document.getElementById('logBromo').value); return isNaN(v) ? null : v; })(),
    ph:         parseFloat(document.getElementById('logPh').value),
    alc:        parseFloat(document.getElementById('logAlc').value),
    cya:        isNaN(cyaRaw)      ? null : cyaRaw,
    turb:       parseFloat(document.getElementById('logTurb').value),
    temp:       parseFloat(document.getElementById('logTemp').value),
    tempAire:   (() => { const v = parseFloat(document.getElementById('logTempAire').value); return isNaN(v) ? null : v; })(),
    humedad:    (() => { const v = parseFloat(document.getElementById('logHumedad').value);  return isNaN(v) ? null : v; })(),
    dureza:     isNaN(durezaRaw)   ? null : durezaRaw,
    banistasMenores: isNaN(banistasMenoresRaw) ? null : banistasMenoresRaw,
    banistasMayores: isNaN(banistasMayoresRaw) ? null : banistasMayoresRaw,
    banistas:        isNaN(banistasRaw)         ? null : banistasRaw,
    orp:        isNaN(orpRaw)      ? null : orpRaw,
    tds:        isNaN(tdsRaw)      ? null : tdsRaw,
    cond:       isNaN(condRaw)     ? null : condRaw,
    caudal:     isNaN(caudalRaw)   ? null : caudalRaw,
    horasFun:   isNaN(horasFunRaw)  ? null : horasFunRaw,
    horasFilt:  isNaN(horasFiltRaw) ? null : horasFiltRaw,
    aguaRep:    isNaN(aguaRepRaw)  ? null : aguaRepRaw,
    retrolav:   isNaN(retrolavRaw) ? null : retrolavRaw,
    presion:    isNaN(presionRaw)  ? null : presionRaw,
    nivelAgua:  (() => { const v = parseFloat(document.getElementById('logNivelAgua').value); return isNaN(v) ? null : v; })(),
    horaInicio: document.getElementById('logHoraInicio').value || null,
    horaFin:    document.getElementById('logHoraFin').value    || null,
    neutralizador: (() => { const v = parseFloat(document.getElementById('logNeutralizador').value); return isNaN(v) ? null : v; })(),
    cloroDos:      (() => { const v = parseFloat(document.getElementById('logCloroDos').value);      return isNaN(v) ? null : v; })(),
    horaAjuste:    document.getElementById('logHoraAjuste').value || null,
    prodQuim:   document.getElementById('logProdQuim').value.trim(),
    averias:    document.getElementById('logAverias').value.trim(),
    notas:      document.getElementById('logNotas').value,
    fotoAgua:   _photos.fotoAgua   || null,
    fotoAveria: _photos.fotoAveria || null,
    labores:    Object.fromEntries(LAB_ITEMS.map(i  => [i.id, !!(document.getElementById('lab_'  + i.id)?.checked)])),
    seguridad:  Object.fromEntries(SEG_ITEMS.map(i  => [i.id, !!(document.getElementById('seg_'  + i.id)?.checked)])),
    instalacion:Object.fromEntries(INST_ITEMS.map(i => [i.id, !!(document.getElementById('inst_' + i.id)?.checked)])),
    aptitud:      document.getElementById('apt_apta')?.checked ? 'apta' : document.getElementById('apt_no_apta')?.checked ? 'no_apta' : null,
    aptitudRazon: (document.getElementById('apt_no_apta')?.checked ? (document.getElementById('aptRazon')?.value.trim() || '') : ''),
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
  entry.islStatus = entry.isl < -0.5 ? 'Corrosiva' : entry.isl < -0.3 ? 'Tend. corrosiva' : entry.isl > 0.5 ? 'Incrustante' : entry.isl > 0.3 ? 'Tend. incrustante' : 'Ideal';
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

async function saveLog() {
  const entry = _buildLogEntry();
  _calcISLForEntry(entry);

  let log = getLog();
  let toastMsg;
  const btn = document.getElementById('btnSaveLog');
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
  if (btn) btn.disabled = true;
  await _secSave('aqua_bitacora', JSON.stringify(log));  // Espera confirmación en disco
  if (btn) btn.disabled = false;
  _checkStorageUsage();
  _logPage = 0;
  clearLogForm();
  renderLog();
  renderDashboardGauges();
  updateIRAPIBitacoraBtn();
  updateReportBtn();
  updateDashReportBtn();
  updateOperadorDatalist();
  showToast(toastMsg, 'success');  // Toast solo aparece cuando el dato YA está en localStorage
  const _aforo = getPerfil().aforo;
  if (_aforo && entry.banistas != null && entry.banistas > _aforo) {
    setTimeout(() => showToast(`⚠ Aforo superado: ${entry.banistas} bañistas registrados (máx. ${_aforo}).`, 'warning', 6000), 600);
  }
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
          <th>Fecha</th><th>Hora</th><th>Operador</th><th>Salvavidas</th>
          <th>Cal.Fís.</th>
          <th>Cl. Libre</th><th>Cl. Comb</th><th>Bromo</th><th>pH</th><th>Alcalinidad</th><th>Dureza</th>
          <th>CYA</th><th>Turbiedad</th><th>T°Agua</th><th>T°Aire</th><th>Humedad</th><th>ORP</th><th>TDS</th><th>Conduct.</th><th>ISL</th><th>Art.16</th><th>Bañistas</th><th>Labores</th><th>Seguridad</th><th>Inst.</th><th>Aptitud</th><th></th>
        </tr>
      </thead>
      <tbody>
        ${pageLog.map(e => `
          <tr class="log-row-clickable" data-ts="${e.ts}" title="Ver detalle del registro">
            <td data-label="Fecha">${escapeHtml(e.fecha) || '–'}</td>
            <td data-label="Hora">${escapeHtml(fmt12h(e.hora))}${e.momento ? `<span class="momento-badge ${e.momento}">${e.momento === 'apertura' ? 'Aper.' : e.momento === 'mediodia' ? 'Medio.' : 'Cierre'}</span>` : ''}</td>
            <td data-label="Operador">${escapeHtml(e.operador) || '–'}</td>
            <td data-label="Salvavidas" title="${e.salvavidasNia ? 'NIA: ' + escapeHtml(e.salvavidasNia) : ''}">${e.salvavidas ? escapeHtml(e.salvavidas) : '–'}</td>
            <td data-label="Cal.Fís.">${(() => { const ok = _fisTodosOk(e); return (e.fisColor || e.fisFlotantes || e.fisOlor || e.fisTransp) ? `<span class="${ok ? 'fis-badge-ok' : 'fis-badge-bad'}">${ok ? '✓' : '⚠'}</span>` : '<span class="fis-badge-na">–</span>'; })()}</td>
            <td data-label="Cl. Libre"${cc('cloro',     e.cloro    )}>${e.cloro     ?? '–'} ppm</td>
            <td data-label="Cl. Comb" ${cc('clorocomb', e.clorocomb)}>${e.clorocomb != null && !isNaN(e.clorocomb) ? e.clorocomb + ' ppm' : '–'}</td>
            <td data-label="Bromo"${e.bromo != null ? (e.bromo >= 2.0 && e.bromo <= 4.0 ? ' class="cell-ok"' : ' class="cell-out"') : ''}>${e.bromo != null ? e.bromo + ' ppm' : '–'}</td>
            <td data-label="pH"       ${cc('ph',         e.ph       )}>${e.ph        ?? '–'}</td>
            <td data-label="Alcalinidad"${cc('alc',   e.alc  )}>${e.alc   ?? '–'} ppm</td>
            <td data-label="Dureza"${cc('dureza', e.dureza)}>${e.dureza != null && !isNaN(e.dureza) ? e.dureza + ' ppm' : '–'}</td>
            <td data-label="CYA"${cc('cya',   e.cya  )}>${e.cya   ?? '–'} ppm</td>
            <td data-label="Turbiedad"${cc('turb',  e.turb )}>${e.turb  ?? '–'} UNT</td>
            <td data-label="T°Agua"${cc('temp', e.temp)}>${e.temp ?? '–'} °C</td>
            <td data-label="T°Aire">${e.tempAire != null ? e.tempAire + ' °C' : '–'}</td>
            <td data-label="Humedad"${e.humedad != null ? (e.humedad >= 40 && e.humedad <= 60 ? ' class="cell-ok"' : ' class="cell-out"') : ''}>${e.humedad != null ? e.humedad + ' %' : '–'}</td>
            <td data-label="ORP"${e.orp != null && !isNaN(e.orp) ? (e.orp <= 700 ? ' class="cell-ok"' : ' class="cell-out"') : ''}>${e.orp != null && !isNaN(e.orp) ? e.orp + ' mV' : '–'}</td>
            <td data-label="TDS"${cc('tds', e.tds)}>${e.tds != null && !isNaN(e.tds) ? e.tds + ' mg/L' : '–'}</td>
            <td data-label="Conduct."${cc('cond', e.cond)}>${e.cond != null && !isNaN(e.cond) ? e.cond + ' µS/cm' : '–'}</td>
            <td data-label="ISL">${e.isl != null ? `<span class="isl-cell ${e.islStatus==='Equilibrada'?'isl-cell-ok':e.islStatus==='Incrustante'?'isl-cell-warn':'isl-cell-danger'}">${e.isl.toFixed(2)}</span>` : '–'}</td>
            <td data-label="Art.16" title="${[e.caudal != null ? 'Caudal: ' + e.caudal + ' m³/h' : '', e.horasFun != null ? 'H. func.: ' + e.horasFun + 'h' : '', e.horasFilt != null ? 'H. filt.: ' + e.horasFilt + 'h' : '', e.aguaRep != null ? 'Agua: ' + e.aguaRep + ' m³' : '', e.retrolav != null ? 'Retrolavados: ' + e.retrolav : '', e.presion != null ? 'Presión: ' + e.presion + ' psi' : '', e.prodQuim ? 'Prod: ' + escapeHtml(e.prodQuim) : '', e.averias ? 'Averías: ' + escapeHtml(e.averias) : ''].filter(Boolean).join(' · ') || 'Sin datos Art.16'}">${(e.caudal != null || e.horasFun != null || e.horasFilt != null || e.aguaRep != null || e.retrolav != null || e.presion != null || e.prodQuim || e.averias) ? '✓' : '–'}</td>
            <td data-label="Bañistas">${(() => {
              const men = e.banistasMenores; const may = e.banistasMayores; const tot = e.banistas;
              if (men == null && may == null) return tot != null ? String(tot) : '–';
              return `<span class="ban-cell"><span class="ban-line"><span class="ban-sub">&lt;6</span>${men ?? '–'}</span><span class="ban-line"><span class="ban-sub">&gt;6</span>${may ?? '–'}</span><span class="ban-total">${tot ?? '–'}</span></span>`;
            })()}</td>
            <td data-label="Labores">${(() => { const n = _labCount(e.labores); return n < 0 ? '<span class="seg-badge seg-badge-none">–</span>' : n === LAB_ITEMS.length ? `<span class="seg-badge seg-badge-ok">✓ ${n}/${LAB_ITEMS.length}</span>` : `<span class="seg-badge seg-badge-warn">⚠ ${n}/${LAB_ITEMS.length}</span>`; })()}</td>
            <td data-label="Seguridad">${(() => { const n = _segCount(e.seguridad); return n < 0 ? '<span class="seg-badge seg-badge-none">–</span>' : n === SEG_ITEMS.length ? `<span class="seg-badge seg-badge-ok">✓ ${n}/${SEG_ITEMS.length}</span>` : `<span class="seg-badge seg-badge-warn">⚠ ${n}/${SEG_ITEMS.length}</span>`; })()}</td>
            <td data-label="Inst.">${(() => { const n = _instCount(e.instalacion); return n < 0 ? '<span class="seg-badge seg-badge-none">–</span>' : n === INST_ITEMS.length ? `<span class="seg-badge seg-badge-ok">✓ ${n}/${INST_ITEMS.length}</span>` : `<span class="seg-badge seg-badge-warn">⚠ ${n}/${INST_ITEMS.length}</span>`; })()}</td>
            <td data-label="Aptitud">${e.aptitud === 'apta' ? '<span class="apt-badge apt-badge-ok">Apta</span>' : e.aptitud === 'no_apta' ? '<span class="apt-badge apt-badge-nok">No apta</span>' : '<span class="apt-badge apt-badge-none">–</span>'}</td>
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

  const momentoLabel = { apertura: 'Apertura', mediodia: 'Mediodía', cierre: 'Cierre' };
  title.textContent = `Registro del ${entry.fecha || '–'}`;
  meta.textContent  = `${fmt12h(entry.hora, '')}${entry.momento ? ' · ' + (momentoLabel[entry.momento] || entry.momento) : ''} · ${entry.operador || 'Sin operador'}`;

  const paramRows = [
    { key: 'cloro',     label: 'Cloro libre residual',  unit: 'ppm',   normMin: 2.0,  normMax: 4.0  },
    { key: 'clorocomb', label: 'Cloro combinado',        unit: 'ppm',   normMin: 0,    normMax: 0.3  },
    { key: 'bromo',     label: 'Bromo total (Br₂)',      unit: 'ppm',   normMin: 2.0,  normMax: 4.0  },
    { key: 'ph',        label: 'pH',                     unit: '',      normMin: 6.8,  normMax: 7.3  },
    { key: 'alc',       label: 'Alcalinidad total',      unit: 'ppm',   normMin: 0,    normMax: 150  },
    { key: 'dureza',    label: 'Dureza cálcica',         unit: 'ppm',   normMin: 200,  normMax: 700  },
    { key: 'cya',       label: 'Estabilizador (CYA)',    unit: 'ppm',   normMin: 0,    normMax: 15   },
    { key: 'turb',      label: 'Transparencia',          unit: 'UNT',   normMin: 0,    normMax: 0.5  },
    { key: 'temp',      label: 'Temperatura del agua',   unit: '°C',    normMin: 0,    normMax: 40   },
    { key: 'tempAire',  label: 'Temperatura del aire',   unit: '°C',    normMin: null, normMax: null },
    { key: 'humedad',   label: 'Humedad relativa',       unit: '%',     normMin: 40,   normMax: 60   },
    { key: 'orp',       label: 'Oxidación (ORP)',        unit: 'mV',    normMin: 0,    normMax: 700, warnBelow: 650 },
    { key: 'tds',       label: 'Sólidos disueltos (TDS)',unit: 'mg/L',  normMin: 1000, normMax: 1200 },
    { key: 'cond',      label: 'Conductividad eléctrica',unit: 'µS/cm', normMin: 2000, normMax: 2400 },
  ];

  const paramHTML = paramRows.map(p => {
    const val = entry[p.key];
    if (val == null || isNaN(val)) return '';
    const hasRange = p.normMin !== null && p.normMax !== null;
    const inRange  = !hasRange || (val >= p.normMin && val <= p.normMax);
    const isWarn   = inRange && p.warnBelow !== undefined && val < p.warnBelow;
    const badge    = !hasRange ? '' : inRange
      ? (isWarn
        ? '<span class="log-detail-badge warn">⚠ Eficacia baja</span>'
        : '<span class="log-detail-badge ok">✓ En rango</span>')
      : '<span class="log-detail-badge out">✗ Fuera</span>';
    let devHTML = '';
    if (hasRange && !inRange) {
      const raw     = val < p.normMin ? val - p.normMin : val - p.normMax;
      const sign    = raw > 0 ? '+' : '−';
      const abs     = parseFloat(Math.abs(raw).toFixed(2));
      const unitLbl = p.unit || 'unidades';
      devHTML = `<span class="log-detail-deviation">${sign}${abs} ${unitLbl} fuera del rango permitido (${p.normMin}–${p.normMax}${p.unit ? ' ' + p.unit : ''})</span>`;
    }
    return `<div class="log-detail-param ${hasRange && !inRange ? 'param-out' : ''}">
      <span class="log-detail-param-label">${p.label}</span>
      <span class="log-detail-param-val">${_safeNum(val)}${p.unit ? ' ' + p.unit : ''}</span>
      ${badge}${devHTML}
    </div>`;
  }).join('');

  const art16Items = [
    (entry.horaInicio || entry.horaFin) ? `<li>Servicio: <strong>${escapeHtml(entry.horaInicio || '?')} – ${escapeHtml(entry.horaFin || '?')}</strong></li>` : '',
    entry.caudal    != null ? `<li>Caudal: <strong>${_safeNum(entry.caudal)} m³/h</strong></li>` : '',
    entry.horasFun  != null ? `<li>Horas de funcionamiento: <strong>${_safeNum(entry.horasFun)} h</strong></li>` : '',
    entry.horasFilt != null ? `<li>Horas de filtración: <strong>${_safeNum(entry.horasFilt)} h</strong></li>` : '',
    entry.aguaRep   != null ? `<li>Agua repuesta: <strong>${_safeNum(entry.aguaRep)} m³</strong></li>` : '',
    entry.retrolav  != null ? `<li>Retrolavados: <strong>${_safeNum(entry.retrolav)}</strong></li>` : '',
    entry.presion   != null ? `<li>Presión filtro: <strong>${_safeNum(entry.presion)} psi</strong></li>` : '',
    entry.nivelAgua != null ? `<li>Nivel del agua: <strong>${_safeNum(entry.nivelAgua)} m</strong>${entry.nivelAgua > 0.6 ? ' <span class="c-danger">⚠ supera 0.6 m</span>' : ''}</li>` : '',
    entry.neutralizador != null ? `<li>Neutralizador (cloro alto): <strong>${_safeNum(entry.neutralizador)} kg/L</strong></li>` : '',
    entry.cloroDos      != null ? `<li>Cloro dosificado (cloro bajo): <strong>${_safeNum(entry.cloroDos)} kg/L</strong></li>` : '',
    (entry.horaAjuste && (entry.neutralizador != null || entry.cloroDos != null)) ? `<li>Hora de ajuste: <strong>${escapeHtml(entry.horaAjuste)}</strong></li>` : '',
    entry.prodQuim              ? `<li>Productos químicos: <strong>${escapeHtml(entry.prodQuim)}</strong></li>` : '',
    entry.averias               ? `<li>Averías / novedades: <strong>${escapeHtml(entry.averias)}</strong></li>` : '',
  ].filter(Boolean).join('');

  const art16HTML = art16Items
    ? `<div class="log-detail-section">
        <div class="log-detail-section-title">Art. 16 — Operación técnica</div>
        <ul class="log-detail-art16">${art16Items}</ul>
      </div>` : '';

  const hasBanistas = entry.banistas != null || entry.banistasMenores != null || entry.banistasMayores != null;
  const banistasHTML = hasBanistas ? `<div class="log-detail-section">
      <div class="log-detail-section-title">Aforo de bañistas</div>
      <div class="ban-detail-grid">
        <div class="ban-detail-card ban-det-menor">
          <span class="ban-det-label">&lt; 6 años</span>
          <strong class="ban-det-val">${entry.banistasMenores ?? '–'}</strong>
        </div>
        <div class="ban-detail-card ban-det-mayor">
          <span class="ban-det-label">&gt; 6 años</span>
          <strong class="ban-det-val">${entry.banistasMayores ?? '–'}</strong>
        </div>
        <div class="ban-detail-card ban-det-total">
          <span class="ban-det-label">Total</span>
          <strong class="ban-det-val">${entry.banistas ?? '–'}</strong>
        </div>
      </div>
    </div>` : '';

  const extraHTML = entry.notas
    ? `<div class="log-detail-section">
        <div class="log-detail-section-title">Notas</div>
        <div class="log-detail-notas"><em>${escapeHtml(entry.notas)}</em></div>
      </div>` : '';

  let islHTML = '';
  if (entry.isl != null) {
    const islCls     = entry.islStatus === 'Equilibrada' ? 'ok' : entry.islStatus === 'Incrustante' ? 'warn' : 'danger';
    const durezaNote = entry.dureza == null ? ` <span class="text-xs-muted">(dureza estimada: ${_safeNum(entry.islDureza)} ppm)</span>` : '';
    islHTML = `<div class="log-detail-section">
      <div class="log-detail-section-title">Índice de Saturación Langelier (ISL)</div>
      <div class="isl-detail-box isl-box-${islCls}">
        <span class="isl-score c-${islCls}">${_safeNum(entry.isl, 2)}</span>
        <div>
          <div class="isl-status c-${islCls}">${entry.islStatus}</div>
          <div class="isl-range-note">Ideal: −0.3 a +0.3 · Aceptable: −0.5 a +0.5${durezaNote}</div>
        </div>
      </div>
    </div>`;
  }

  let labHTML = '';
  if (entry.labores) {
    const n = _labCount(entry.labores);
    labHTML = `<div class="log-detail-section">
      <div class="log-detail-section-title">Labores diarias — ${n}/${LAB_ITEMS.length} realizadas</div>
      <div class="seg-detail-grid">
        ${LAB_ITEMS.map(i => `<div class="seg-detail-item ${entry.labores[i.id] ? 'seg-det-ok' : 'seg-det-nok'}">
          <span class="seg-det-icon">${entry.labores[i.id] ? '✓' : '✗'}</span>
          <span>${i.label}</span>
        </div>`).join('')}
      </div>
    </div>`;
  }

  let segHTML = '';
  if (entry.seguridad) {
    const n = _segCount(entry.seguridad);
    segHTML = `<div class="log-detail-section">
      <div class="log-detail-section-title">Seguridad diaria — ${n}/${SEG_ITEMS.length} verificados</div>
      <div class="seg-detail-grid">
        ${SEG_ITEMS.map(i => `<div class="seg-detail-item ${entry.seguridad[i.id] ? 'seg-det-ok' : 'seg-det-nok'}">
          <span class="seg-det-icon">${entry.seguridad[i.id] ? '✓' : '✗'}</span>
          <span>${i.label}</span>
        </div>`).join('')}
      </div>
    </div>`;
  }

  let instHTML = '';
  if (entry.instalacion) {
    const n = _instCount(entry.instalacion);
    instHTML = `<div class="log-detail-section">
      <div class="log-detail-section-title">Instalación (Alist. 7) — ${n}/${INST_ITEMS.length} aceptables</div>
      <div class="seg-detail-grid">
        ${INST_ITEMS.map(i => `<div class="seg-detail-item ${entry.instalacion[i.id] ? 'seg-det-ok' : 'seg-det-nok'}">
          <span class="seg-det-icon">${entry.instalacion[i.id] ? '✓' : '✗'}</span>
          <span>${i.label}</span>
        </div>`).join('')}
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

  const aptHTML = entry.aptitud ? (() => {
    const isApta = entry.aptitud === 'apta';
    return `<div class="apt-detail-banner ${isApta ? 'apt-det-ok' : 'apt-det-nok'}">
      <span class="apt-det-icon">${isApta ? '✓' : '✗'}</span>
      <div>
        <strong>${isApta ? '1. Apta para el servicio' : '2. No apta para el servicio'}</strong>
        ${!isApta && entry.aptitudRazon ? `<div class="apt-det-razon">${escapeHtml(entry.aptitudRazon)}</div>` : ''}
      </div>
    </div>`;
  })() : '';

  const _fisBadge = (key, val) => {
    if (!val) return '<span class="badge-na">–</span>';
    const good = {fisColor:'aceptable', fisFlotantes:'ausentes', fisOlor:'aceptable', fisTransp:'visible'}[key];
    const cls  = val === good ? 'badge-ok' : 'badge-out';
    return `<span class="${cls}">${_FIS_LABELS[val] || val}</span>`;
  };
  const hasFis = entry.fisColor || entry.fisFlotantes || entry.fisOlor || entry.fisTransp;
  const fisHTML = hasFis ? `<div class="log-detail-section">
    <div class="log-detail-section-title">Calidad física del agua</div>
    <div class="log-detail-extra-row"><span>Color (visual)</span><strong>${_fisBadge('fisColor', entry.fisColor)}</strong></div>
    <div class="log-detail-extra-row"><span>Materias flotantes</span><strong>${_fisBadge('fisFlotantes', entry.fisFlotantes)}</strong></div>
    <div class="log-detail-extra-row"><span>Olor (olfativo)</span><strong>${_fisBadge('fisOlor', entry.fisOlor)}</strong></div>
    <div class="log-detail-extra-row"><span>Transparencia</span><strong>${_fisBadge('fisTransp', entry.fisTransp)}</strong></div>
  </div>` : '';

  const personalHTML = (entry.salvavidas || entry.salvavidasNia) ? `<div class="log-detail-section">
    <div class="log-detail-section-title">Personal de turno</div>
    <div class="log-detail-extra-row"><span>Operador</span><strong>${escapeHtml(entry.operador || '–')}</strong></div>
    <div class="log-detail-extra-row"><span>Salvavidas</span><strong>${escapeHtml(entry.salvavidas || '–')}</strong></div>
    ${entry.salvavidasNia ? `<div class="log-detail-extra-row"><span>NIA</span><strong>${escapeHtml(entry.salvavidasNia)}</strong></div>` : ''}
  </div>` : '';

  body.innerHTML = `
    ${aptHTML}
    ${islHTML}
    ${fisHTML}
    ${personalHTML}
    <div class="log-detail-section">
      <div class="log-detail-section-title">Parámetros del agua</div>
      <div class="log-detail-params">${paramHTML || '<p class="log-detail-empty">Sin parámetros registrados.</p>'}</div>
    </div>
    ${art16HTML}
    ${banistasHTML}
    ${labHTML}
    ${segHTML}
    ${instHTML}
    ${extraHTML}
    ${fotosHTML}
    <div class="detail-actions">
      <button class="btn btn-outline btn-danger-outline js-log-detail-delete btn-flex">
        <svg class="btn-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
        Eliminar
      </button>
      <button class="btn btn-outline js-log-detail-edit btn-flex">
        <svg class="btn-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
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
    { title: 'Notificar autoridad sanitaria', desc: 'Notifique de inmediato a la Secretaría de Salud local o autoridad sanitaria competente. El Art. 6 núm. 6 y Art. 15 núm. 5 de la Res. 234/2026 exigen notificación ante todo evento diarreico (máx. 5 días). Registre la hora de notificación y el funcionario contactado.' },
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
  sangre: [
    { title: 'Evacuar la piscina', desc: 'Solicite a todos los bañistas salir del agua de inmediato. Restrinja el acceso al área.' },
    { title: 'Identificar el incidente', desc: 'Confirme la presencia de sangre. Registre la hora exacta y la zona afectada. Identifique al bañista involucrado si es posible.' },
    { title: 'Remover el residuo', desc: 'Use una red dedicada. Coloque el material en bolsa hermética y deséchelo como residuo biológico.' },
    { title: 'Hipercloración', desc: 'Eleve el cloro residual a 10 ppm. Tiempo mínimo de contacto: 30 minutos con pH entre 6.8 y 7.3.' },
    { title: 'Verificar pH', desc: 'Mantenga el pH entre 6.8 y 7.3 durante todo el proceso para garantizar la eficacia desinfectante del cloro.' },
    { title: 'Filtrar y registrar', desc: 'Active el sistema de filtración. Registre el incidente en la bitácora con hora, bañistas presentes y operador a cargo.' },
    { title: 'Reapertura', desc: 'Reabra solo tras verificar cloro ≥ 2 ppm, pH 6.8–7.3 y turbiedad ≤ 0.5 UNT.' },
  ],
  quimicos: [
    { title: 'Evacuar la piscina de inmediato', desc: 'Retire a todos los bañistas del agua y del área circundante. Restrinja el acceso. No permita el ingreso sin equipos de protección personal.' },
    { title: 'Identificar el agente químico', desc: 'Determine qué producto se derramó consultando la ficha técnica o etiqueta. NO agregue correctivos ni contrarreactivos sin conocer el agente — una reacción incorrecta puede generar gases tóxicos.' },
    { title: 'Ventilar el área', desc: 'Si la instalación es cubierta, abra ventanas y puertas para garantizar circulación de aire. En exteriores, mantenga alejadas a las personas de la zona afectada y de los vapores.' },
    { title: 'Notificar a autoridad sanitaria y emergencias', desc: 'Contacte a la Secretaría de Salud local y a la línea de emergencias química. Bomberos / CISPROQUIM: 018000 916012. Registre la hora de notificación y el funcionario contactado.' },
    { title: 'No reabrir sin análisis de laboratorio', desc: 'No corrija el agua a ciegas. Espere el resultado de un análisis de laboratorio que valide pH, cloro, conductividad y ausencia de contaminantes antes de cualquier acción correctiva.' },
    { title: 'Aplicar correctivos y filtrar', desc: 'Una vez identificado el agente y con concepto de la autoridad sanitaria, aplique los correctivos indicados y active la filtración continua. Registre cada acción tomada.' },
    { title: 'Reapertura', desc: 'Solo reabra cuando la autoridad sanitaria lo autorice expresamente y los parámetros (cloro 2–4 ppm, pH 6.8–7.3, turbiedad ≤ 0.5 UNT) estén en rango.' },
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

  const HYPER_STEP = APP.afrType === 'diarreico' ? 4 : APP.afrType === 'quimicos' ? -1 : 3;
  if (HYPER_STEP < 0 || APP.afrStep !== HYPER_STEP) { block.hidden = true; return; }
  block.hidden = false;

  const TARGET = { solido: 10, diarreico: 20, vomito: 2, sangre: 10 };
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
         <div class="input-unit calc-input-narrow">
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
  const TARGET = { solido: 10, diarreico: 20, vomito: 2, sangre: 10 };
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
    ? `<div class="afr-dose-row u-mb4"><span>Diferencia a agregar</span><strong>${delta.toFixed(1)} ppm</strong></div>` : '';

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
  document.getElementById('btnSangre').classList.toggle('active',    type === 'sangre');
  document.getElementById('btnQuimicos').classList.toggle('active',  type === 'quimicos');
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
    const isSang = i.tipo === 'sangre';
    const isQui  = i.tipo === 'quimicos';
    const incClass   = isDiar ? 'afr-inc-diarreico' : isVom ? 'afr-inc-vomito' : isSang ? 'afr-inc-sangre' : isQui ? 'afr-inc-quimicos' : 'afr-inc-solido';
    const badgeClass = isDiar ? 'afr-inc-badge-emergencia' : isVom ? 'afr-inc-badge-vomito' : isSang ? 'afr-inc-badge-sangre' : isQui ? 'afr-inc-badge-quimicos' : 'afr-inc-badge-solido';
    const badgeText  = isDiar ? 'EMERGENCIA' : isVom ? 'Vómito' : isSang ? 'Sangre' : isQui ? 'Químico' : 'Sólido';
    const iconColor  = isDiar ? '#dc2626' : isVom ? '#d97706' : isSang ? '#be123c' : isQui ? '#7c3aed' : 'var(--warning)';
    return `
    <div class="afr-incident-item ${incClass}" data-ts="${i.ts}" title="Ver detalle del incidente">
      <div class="afr-incident-info">
        <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="2" class="u-shrink-0"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <div>
          <strong>${escapeHtml(_afrFechaDisplay(i))} · ${escapeHtml(fmt12h(i.hora, ''))}</strong>
          <span class="afr-inc-badge ${badgeClass}">${badgeText}</span><br>
          <span class="detail-meta">Operador: ${escapeHtml(i.operador) || '–'}</span>
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
  const isSang = i.tipo === 'sangre';
  const isQui  = i.tipo === 'quimicos';
  const tipoLabel  = isDiar ? 'Diarreico' : isVom ? 'Vómito' : isSang ? 'Sangre' : isQui ? 'Químico' : 'Sólido';
  const badgeClass = isDiar ? 'afr-inc-badge-emergencia' : isVom ? 'afr-inc-badge-vomito' : isSang ? 'afr-inc-badge-sangre' : isQui ? 'afr-inc-badge-quimicos' : 'afr-inc-badge-solido';
  const badgeText  = isDiar ? 'EMERGENCIA' : isVom ? 'Vómito' : isSang ? 'Sangre' : isQui ? 'Químico' : 'Sólido';
  const protDesc   = isDiar
    ? 'Hipercloración a 20 ppm · Cierre mínimo 13 horas · Riesgo de Cryptosporidium. Se requiere notificación a autoridad sanitaria.'
    : isVom
    ? 'Ajuste de cloro libre a 2 ppm · Inspección y limpieza inmediata del área afectada.'
    : isSang
    ? 'Hipercloración a 10 ppm · Tiempo de contacto mínimo 30 minutos · pH 6.8–7.3.'
    : isQui
    ? 'No aplicar correctivos sin identificar el agente. Notificar autoridad sanitaria y CISPROQUIM. Esperar análisis de laboratorio.'
    : 'Extracción física del material · Sin cierre obligatorio · Verificar niveles de cloro residual.';

  document.getElementById('afrDetailTitle').innerHTML =
    `Incidente AFR <span class="afr-inc-badge ${badgeClass}">${badgeText}</span>`;
  document.getElementById('afrDetailMeta').textContent =
    `${i.fecha || '–'} · ${fmt12h(i.hora, '')} · ${i.operador || 'Sin operador'}`;

  const hasCierre = i.fechaReapertura || i.cloroFinal != null || i.phFinal != null || i.turbFinal != null;
  const cierreSection = hasCierre
    ? `<div class="log-detail-section">
        <div class="log-detail-section-title section-title-ok">✓ Cierre del protocolo</div>
        ${i.cloroFinal != null ? `<div class="log-detail-param"><span class="log-detail-param-label">Cloro libre post-tratamiento</span><span class="log-detail-param-val">${i.cloroFinal} ppm ${i.cloroFinal >= 2 && i.cloroFinal <= 4 ? '<span class="log-detail-badge ok">✓ En rango</span>' : '<span class="log-detail-badge out">✗ Fuera</span>'}</span></div>` : ''}
        ${i.phFinal    != null ? `<div class="log-detail-param"><span class="log-detail-param-label">pH post-tratamiento</span><span class="log-detail-param-val">${i.phFinal} ${i.phFinal >= 6.8 && i.phFinal <= 7.3 ? '<span class="log-detail-badge ok">✓ En rango</span>' : '<span class="log-detail-badge out">✗ Fuera</span>'}</span></div>` : ''}
        ${i.turbFinal  != null ? `<div class="log-detail-param"><span class="log-detail-param-label">Turbiedad post-tratamiento</span><span class="log-detail-param-val">${i.turbFinal} UNT ${i.turbFinal <= 0.5 ? '<span class="log-detail-badge ok">✓ ≤ 0.5</span>' : '<span class="log-detail-badge out">✗ > 0.5</span>'}</span></div>` : ''}
        ${i.fechaReapertura ? `<div class="log-detail-param"><span class="log-detail-param-label">Reapertura</span><span class="log-detail-param-val">${i.fechaReapertura}${i.horaReapertura ? ' · ' + fmt12h(i.horaReapertura) : ''}</span></div>` : ''}
      </div>`
    : `<div class="log-detail-section">
        <div class="afr-pending-banner">
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
      <div class="log-detail-section-title">Protocolo de respuesta sanitaria aplicado</div>
      <p class="afr-proto-desc">${protDesc}</p>
    </div>
    ${cierreSection}
    ${i.foto ? `<div class="log-detail-section">
      <div class="log-detail-section-title">Evidencia fotográfica</div>
      <div class="log-detail-fotos">
        <div class="log-detail-foto-item"><span class="log-detail-foto-label">Foto del incidente</span><img class="log-detail-foto-img" src="${_safePhotoSrc(i.foto)}" alt="Foto del incidente AFR" /></div>
      </div>
    </div>` : ''}
    <div class="detail-actions">
      <button class="btn btn-outline js-afr-detail-edit btn-flex">
        <svg class="btn-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        Editar
      </button>
      <button class="btn btn-primary js-afr-detail-close btn-flex">Cerrar</button>
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

function setRepMes(offset) {
  const d = new Date();
  d.setMonth(d.getMonth() + offset);
  const y = d.getFullYear();
  const m = d.getMonth();
  const desde   = `${y}-${String(m + 1).padStart(2, '0')}-01`;
  const lastDay = new Date(y, m + 1, 0).getDate();
  const hasta   = `${y}-${String(m + 1).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}`;
  const dEl = document.getElementById('repDesde');
  const hEl = document.getElementById('repHasta');
  if (dEl) dEl.value = desde;
  if (hEl) hEl.value = hasta;
  const btn = document.getElementById('btnClearRepRange');
  if (btn) btn.disabled = false;
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

function _prefillReporteFromPerfil() {
  const p = getPerfil();
  const data = JSON.parse(localStorage.getItem('aqua_reporte') || '{}');
  const setIfEmpty = (id, val) => {
    const el = document.getElementById(id);
    if (el && !el.value && val) el.value = val;
  };
  setIfEmpty('repNombre',      data.repNombre      || p.razonSocial);
  setIfEmpty('repResponsable', data.repResponsable || p.propietario);
  setIfEmpty('repUbicacion',   data.repUbicacion   || [p.municipio, p.departamento].filter(Boolean).join(', '));
  setIfEmpty('repVolumen',     data.repVolumen      || (p.volumen ? p.volumen.toFixed(1) : ''));
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
  document.getElementById('repAlc').textContent   = pct(e => e.alc  <= 150);
  document.getElementById('repCya').textContent   = pctOpt(e => e.cya != null && !isNaN(e.cya), e => e.cya >= 0 && e.cya <= 15);
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
  const csvBtn = document.getElementById('btnExportCSV');
  if (csvBtn) csvBtn.disabled = !ready;
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
  const loadScript = (src, cb) => {
    const s = document.createElement('script');
    s.src = src;
    s.onload = cb;
    s.onerror = onError;
    document.head.appendChild(s);
  };

  loadScript(
    './lib/jspdf.umd.min.js',
    () => loadScript(
      './lib/jspdf.plugin.autotable.min.js',
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
    const [logoAquaB64, logoEstabB64, logHash] = await Promise.all([
      _loadImgB64('Multimedia/logo1.png').catch(() => null),
      _loadImgB64('Multimedia/logo1.webp').catch(() => null),
      _sha256Hex(localStorage.getItem('aqua_bitacora') || '[]'),
    ]);
    await __buildPDF(logoAquaB64, logoEstabB64, integrity, logHash);
  } catch (err) {
    showToast('Error al generar el PDF. Intenta de nuevo.', 'error');
  } finally {
    if (btn && btn.dataset.orig) { btn.disabled = false; btn.innerHTML = btn.dataset.orig; delete btn.dataset.orig; }
  }
}

async function __buildPDF(logoAquaB64, logoEstabB64, integrity, logHash) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  const _pf         = getPerfil();
  const nombre      = document.getElementById('repNombre').value      || _pf.razonSocial || 'Sin nombre';
  const responsable = document.getElementById('repResponsable').value  || _pf.propietario || '–';
  const ubicacion   = document.getElementById('repUbicacion').value   || [_pf.municipio, _pf.departamento].filter(Boolean).join(', ') || '–';
  const volumen     = document.getElementById('repVolumen').value      || (_pf.volumen ? _pf.volumen.toFixed(1) : '–');
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
  const hashShort = logHash ? logHash.slice(0, 16) + '...' + logHash.slice(-8) : '-';

  // ── Metadata del documento ────────────────────────────────
  doc.setProperties({
    title:    `Reporte Calidad del Agua — ${nombre}`,
    subject:  `Período: ${periodo}`,
    author:   responsable,
    creator:  'Aqua Tech · PWA · Res. 234/2026',
    keywords: 'piscina, calidad agua, resolución 234, Colombia',
  });

  // ── Membrete ─────────────────────────────────────────────
  // Área blanca superior
  doc.setFillColor(255, 255, 255);
  doc.rect(0, 0, 210, 28, 'F');

  if (logoEstabB64) {
    // ── Layout dual: logo establecimiento izquierda · Aquatech derecha ──
    // Logo del establecimiento (el nombre ya va dentro del logo)
    doc.addImage(logoEstabB64, 'WEBP', 8, 2, 22, 22);

    // Solo ubicación debajo del logo (el nombre está en la imagen)
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text(ubicacion.length > 45 ? ubicacion.slice(0, 43) + '…' : ubicacion, 33, 18);

    // Separador vertical
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.3);
    doc.line(128, 4, 128, 24);

    // Logo Aquatech (derecha, más pequeño — rol de sistema soporte)
    if (logoAquaB64) {
      doc.addImage(logoAquaB64, 'PNG', 132, 4, 13, 18);
    }
    doc.setTextColor(30, 41, 59);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.text('Aqua Tech', logoAquaB64 ? 148 : 132, 11);
    doc.setFontSize(6.5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text('Sistema de Gestión · Res. 234/2026', logoAquaB64 ? 148 : 132, 17);
    doc.text(`Generado: ${genLocal}`, 198, 23, { align: 'right' });

  } else {
    // ── Layout original: solo Aquatech ──
    if (logoAquaB64) {
      doc.addImage(logoAquaB64, 'PNG', 10, 2, 15, 21);
    }
    doc.setTextColor(30, 41, 59);
    doc.setFontSize(15);
    doc.setFont('helvetica', 'bold');
    doc.text('Aqua Tech', 29, 11);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text('Sistema de Gestión de Piscinas · Resolución 234 / 2026 · Colombia', 29, 18);
    doc.text(`Generado: ${genLocal}`, 196, 11, { align: 'right' });
  }

  // Banda oscura
  doc.setFillColor(30, 41, 59);
  doc.rect(0, 28, 210, 13, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text('Reporte Mensual de Calidad del Agua', 105, 33, { align: 'center' });
  doc.setFontSize(7.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184);
  doc.text('Publicación obligatoria · Art. 16 §2 · Resolución 234 de 2026 · Colombia', 105, 38.5, { align: 'center' });

  // ── Datos del establecimiento ────────────────────────────
  doc.setTextColor(30, 41, 59);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.text('Datos del establecimiento', 14, 51);

  const _pfRows = [
    ['Nombre / Razón social', nombre,                         'Responsable',  responsable],
    ['Ubicación',             ubicacion,                      'Volumen base', volumen + ' m³'],
    _pf.nit       ? ['NIT',            _pf.nit,       'Matrícula', _pf.matricula || '–'] : null,
    _pf.tipoUso   ? ['Tipo de uso',    _pf.tipoUso === 'colectivo' ? 'Colectivo' : 'Restringido', 'Sistema',    _pf.sistemaOp === 'recirculacion' ? 'Recirculación' : _pf.sistemaOp === 'desalojo' ? 'Desalojo' : '–'] : null,
    (_pf.largo && _pf.ancho) ? ['Dimensiones', `${_pf.largo} × ${_pf.ancho} m`, 'Perímetro', (2 * (_pf.largo + _pf.ancho)).toFixed(2) + ' m'] : null,
    _pf.aforo     ? ['Aforo máximo',   _pf.aforo + ' bañistas simultáneos', '', ''] : null,
    _pf.opNombre  ? ['Operador',       _pf.opNombre + (_pf.opNit ? ' · NIT ' + _pf.opNit : ''), 'Período', periodo] : ['Período', periodo, '', ''],
  ].filter(Boolean);

  doc.autoTable({
    startY: 55,
    body: _pfRows,
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
    { label: 'Bromo total (Br2)',    unit: 'ppm', field: 'bromo',     dec: 1, ok: e => e.bromo == null || (e.bromo >= 2.0 && e.bromo <= 4.0), range: '2.0 – 4.0 ppm'  },
    { label: 'pH',                   unit: '',    field: 'ph',        dec: 2, ok: e => e.ph   >= 6.8 && e.ph   <= 7.3,                                                    range: '6.8 – 7.3'     },
    { label: 'Alcalinidad total',     unit: 'ppm', field: 'alc',    dec: 0, ok: e => e.alc    <= 150, range: 'Ideal: 80–120 · Máx. 150 ppm' },
    { label: 'Dureza cálcica',        unit: 'ppm', field: 'dureza', dec: 0, ok: e => e.dureza == null || (e.dureza >= 200 && e.dureza <= 700), range: '200 – 700 ppm'  },
    { label: 'Estabilizador (CYA)',    unit: 'ppm', field: 'cya',    dec: 0, ok: e => e.cya == null || (e.cya >= 0 && e.cya <= 15), range: '0 – 15 ppm' },
    { label: 'Transparencia / Turbiedad', unit: 'UNT', field: 'turb', dec: 2, ok: e => e.turb >= 0   && e.turb <= 0.5,  range: '0 – 0.5 UNT'    },
    { label: 'Temperatura del agua',  unit: 'C',    field: 'temp',     dec: 1, ok: e => { const v = +e.temp;     return isNaN(v) ? true : v <= 40; },          range: 'max. 40 C'        },
    { label: 'Temperatura del aire',  unit: 'C',    field: 'tempAire', dec: 1, ok: () => true,                                                              range: 'Informativo'      },
    { label: 'Humedad relativa',      unit: '%',    field: 'humedad',  dec: 0, ok: e => { const v = +e.humedad; return isNaN(v) ? true : v >= 40 && v <= 60; }, range: '40 – 60 %'   },
    { label: 'Potencial redox (ORP)',  unit: 'mV',   field: 'orp',     dec: 0, ok: e => { const v = +e.orp;     return isNaN(v) ? true : v >= 0 && v <= 700; }, range: '0 – 700 mV'  },
    { label: 'Sólidos disueltos (TDS)',unit: 'mg/L', field: 'tds',  dec: 0, ok: e => e.tds  == null || (e.tds  >= 1000 && e.tds  <= 1200), range: '1000 – 1200 mg/L'   },
    { label: 'Conductividad electrica', unit: 'uS/cm',field: 'cond', dec: 0, ok: e => e.cond == null || (e.cond >= 2000 && e.cond <= 2400), range: '2000 - 2400 uS/cm'  },
    { label: 'Nivel del agua (bajo borda)', unit: 'm',  field: 'nivelAgua', dec: 2, ok: e => e.nivelAgua == null || e.nivelAgua <= 0.6, range: 'max. 0.6 m'         },
    { label: 'Color del agua (visual)',     categorical: true, range: 'Aceptable',    ok: e => !e.fisColor     || e.fisColor     === 'aceptable' },
    { label: 'Materias flotantes',          categorical: true, range: 'Ausentes',     ok: e => !e.fisFlotantes || e.fisFlotantes === 'ausentes'  },
    { label: 'Olor del agua (olfativo)',    categorical: true, range: 'Aceptable',    ok: e => !e.fisOlor      || e.fisOlor      === 'aceptable' },
    { label: 'Transparencia (fondo visible)',categorical: true, range: 'Fondo visible',ok: e => !e.fisTransp   || e.fisTransp    === 'visible'   },
  ];

  doc.autoTable({
    startY: doc.lastAutoTable.finalY + 16,
    head: [['Parámetro', 'Rango normativo', 'Promedio', 'Mín', 'Máx', '% en rango']],
    body: [
      [{ content: `Mediciones: ${log.length}   ·   Incidentes AFR: ${incidents.length}`, colSpan: 6, styles: { fontStyle: 'bold', halign: 'center' } }],
      ...paramRows.map(p => {
        if (p.categorical) {
          const pc = _pct(p.ok);
          return [p.label, p.range, '–', '–', '–', pc != null ? pc + '%' : '–'];
        }
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
      (e.alc != null && !isNaN(e.alc) && e.alc > 150) ||
      (e.ph  != null && !isNaN(e.ph)  && (e.ph  < 6.8 || e.ph  > 7.3))
    ).length;
    const ncOtros = log.filter(e =>
      (e.turb != null && !isNaN(e.turb) && e.turb > 0.5) ||
      (e.cya  != null && !isNaN(e.cya)  && e.cya  > 15)  ||
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
        ['pH / ORP / CYA',   pAlk   + '%',    '30% (55% s/micro)', (pAlk   * (30/55)).toFixed(1)],
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
      head: [['Fecha', 'Hora', 'Operador', 'Salvavidas', 'Cl.L', 'Cl.C', 'Br₂', 'pH', 'Alc.', 'CYA', 'Turb.', 'T°Agua', 'T°Aire', 'HR%', 'ORP', '<6a', '>6a', 'Tot.', 'Notas']],
      body: log.map(e => [
        e.fecha    || '–',
        fmt12h(e.hora),
        e.operador || '–',
        e.salvavidas ? e.salvavidas + (e.salvavidasNia ? '\n' + e.salvavidasNia : '') : '–',
        (e.cloro     ?? '–') + ' ppm',
        (e.clorocomb != null && !isNaN(e.clorocomb) ? e.clorocomb + ' ppm' : '–'),
        (e.bromo     != null ? e.bromo + ' ppm' : '–'),
        e.ph       ?? '–',
        (e.alc  ?? '–') + ' ppm',
        (e.cya  ?? '–') + ' ppm',
        (e.turb    ?? '–') + ' UNT',
        (e.temp    ?? '–') + ' °C',
        (e.tempAire != null ? e.tempAire + ' °C' : '–'),
        (e.humedad  != null ? e.humedad  + ' %'  : '–'),
        (e.orp  != null && !isNaN(e.orp) ? e.orp + ' mV' : '–'),
        e.banistasMenores ?? '–',
        e.banistasMayores ?? '–',
        e.banistas        ?? '–',
        e.notas    || '',
      ]),
      theme: 'striped',
      headStyles: { fillColor: [30, 41, 59], textColor: 255, fontStyle: 'bold' },
      styles:     { fontSize: 6.5, cellPadding: 1.0 },
      columnStyles: { 12: { cellWidth: 28 } },
      margin: { left: 14, right: 14 },
    });
  }

  // ── Analisis de laboratorio (Art. 11) ────────────────────
  let labEndY = doc.lastAutoTable ? doc.lastAutoTable.finalY : 10;
  {
    const labRecs = getLabRecords();
    const pageH   = doc.internal.pageSize.getHeight();
    let lY = labEndY + 16;
    if (lY + 44 > pageH - 15) { doc.addPage(); lY = 20; }

    doc.setFontSize(11); doc.setFont('helvetica', 'bold'); doc.setTextColor(30, 41, 59);
    doc.text('Analisis de laboratorio — Art. 11 Res. 234/2026', 14, lY);

    if (!labRecs.length) {
      doc.setFontSize(9); doc.setFont('helvetica', 'normal'); doc.setTextColor(100);
      doc.text('Sin registros de laboratorio en el periodo.', 14, lY + 8);
      labEndY = lY + 18;
    } else {
      const RESULT = v => v === 'ausente' ? 'Ausente' : v === 'presente' ? 'Presente' : '-';
      const labRows = labRecs.slice(0, 6).map(r => [
        r.fecha       || '-',
        r.laboratorio || '-',
        r.acreditacion || '-',
        RESULT(r.coliformes),
        RESULT(r.ecoli),
        RESULT(r.pseudomonas),
        RESULT(r.staph),
        r.cya != null ? r.cya + ' mg/L' : '-',
      ]);
      doc.autoTable({
        startY: lY + 5,
        head: [['Fecha muestra', 'Laboratorio', 'Acreditacion', 'Coliformes', 'E. coli', 'Pseudomonas', 'Staph.', 'CYA']],
        body: labRows,
        theme: 'striped',
        headStyles: { fillColor: [2, 62, 138], textColor: 255, fontStyle: 'bold', fontSize: 7 },
        styles: { fontSize: 7, cellPadding: 1.5 },
        columnStyles: {
          0: { cellWidth: 22 }, 1: { cellWidth: 36 }, 2: { cellWidth: 22 },
          3: { cellWidth: 20 }, 4: { cellWidth: 16 }, 5: { cellWidth: 22 },
          6: { cellWidth: 16 }, 7: { cellWidth: 18 },
        },
        didParseCell: data => {
          if (data.section === 'body') {
            const v = data.cell.raw;
            if (v === 'Presente') { data.cell.styles.textColor = [185, 28, 28]; data.cell.styles.fontStyle = 'bold'; }
            if (v === 'Ausente')  { data.cell.styles.textColor = [22, 101, 52]; }
          }
        },
        margin: { left: 14, right: 14 },
      });
      labEndY = doc.lastAutoTable.finalY;
    }
  }

  // ── Incidentes AFR ───────────────────────────────────────
  const afrPageH = doc.internal.pageSize.getHeight();
  let afrY = labEndY + 16;
  if (afrY + 40 > afrPageH - 15) { doc.addPage(); afrY = 20; }

  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 41, 59);
  doc.text('Protocolo AFR — Incidentes del periodo', 14, afrY);

  let afterAfrY = afrY + 14;

  if (incidents.length === 0) {
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100);
    doc.text('Sin incidentes AFR registrados en este periodo.', 14, afrY + 8);
    afterAfrY = afrY + 18;
  } else {
    doc.autoTable({
      startY: afrY + 6,
      head: [['Fecha', 'Hora', 'Tipo / Severidad', 'Operador', 'Cl. final', 'pH final', 'Turb. final', 'Reapertura']],
      body: incidents.map(i => {
        const reapertura = i.fechaReapertura
          ? `${i.fechaReapertura}${i.horaReapertura ? ' ' + fmt12h(i.horaReapertura) : ''}`
          : '–';
        return [
          i.fecha    || '–',
          fmt12h(i.hora),
          i.tipo === 'diarreico' ? 'Diarreico — EMERGENCIA (Cryptosporidium)' : i.tipo === 'vomito' ? 'Vómito' : i.tipo === 'sangre' ? 'Sangre' : i.tipo === 'quimicos' ? 'Derrame químico' : 'Sólido',
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
        } else if (tipo === 'sangre') {
          data.cell.styles.fillColor = [255, 228, 230];
          data.cell.styles.textColor = [159, 18, 57];
        } else if (tipo === 'quimicos') {
          data.cell.styles.fillColor = [237, 233, 254];
          data.cell.styles.textColor = [91, 33, 182];
        }
      },
      margin: { left: 14, right: 14 },
    });
  }

  // ── Sección de verificación de integridad ────────────────
  {
    const pageH = doc.internal.pageSize.getHeight();
    const afrFinalY = incidents.length > 0 && doc.lastAutoTable ? doc.lastAutoTable.finalY : afterAfrY;
    let vY = afrFinalY + 16;
    if (vY + 38 > pageH - 20) { doc.addPage(); vY = 20; }

    const integrityOk = integrity?.clean !== false;
    const hmacLabel   = integrityOk
      ? 'Valida — sin modificaciones externas detectadas'
      : `Falla detectada en: ${integrity.tampered.map(c => c.key).join(', ')}`;

    // Título neutro de sección
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 41, 59);
    doc.text('Verificacion del documento', 14, vY);

    doc.autoTable({
      startY: vY + 5,
      body: [
        ['Estado del documento',          hmacLabel],
        ['Fecha de generacion',           genLocal],
        ['Codigo de verificacion',        hashShort],
        ['Origen de los datos',           'Aqua Tech - almacenamiento local del dispositivo'],
        ['Advertencia legal',             'Este documento fue generado por una aplicacion cliente. No constituye un registro oficial certificado por autoridad sanitaria. La integridad de los datos depende del dispositivo y del navegador del operador.'],
      ],
      theme: 'plain',
      styles:      { fontSize: 8, cellPadding: 2.5 },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 60, textColor: [100, 116, 139] },
        1: { cellWidth: 126 },
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.row.index === 0) {
          data.cell.styles.textColor = integrityOk ? [22, 101, 52] : [185, 28, 28];
          data.cell.styles.fontStyle = 'bold';
        }
        if (data.section === 'body' && data.row.index === 4) {
          data.cell.styles.textColor = [150, 150, 150];
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
      `Aqua Tech · Res. 234 / 2026 · Página ${i} de ${pages}`,
      105, doc.internal.pageSize.getHeight() - 8,
      { align: 'center' }
    );
  }

  const fileName = `Reporte_Mensual_${nombre.replace(/\s+/g, '_')}_${desde || 'sin-fecha'}.pdf`;
  const isMobile = navigator.maxTouchPoints > 0 && /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
  if (isMobile) {
    const blob = doc.output('blob');
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.target   = '_blank';
    a.rel      = 'noopener';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  } else {
    doc.save(fileName);
  }
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
    fillEl.style.background = pct === 100 ? '#0cb86a' : pct >= 60 ? '#f59e0b' : '#dc2626';
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

// ── PERFIL DEL ESTABLECIMIENTO ───────────────────────────
const PERFIL_KEY = 'aqua_perfil';

function getPerfil() {
  try { return JSON.parse(localStorage.getItem(PERFIL_KEY) || '{}'); } catch { return {}; }
}

function savePerfil() {
  if (!_requireUnlocked()) return;
  const p = {
    razonSocial:   document.getElementById('pfRazonSocial').value.trim(),
    matricula:     document.getElementById('pfMatricula').value.trim(),
    nit:           document.getElementById('pfNit').value.trim(),
    direccion:     document.getElementById('pfDireccion').value.trim(),
    municipio:     document.getElementById('pfMunicipio').value.trim(),
    departamento:  document.getElementById('pfDepartamento').value.trim(),
    telefono:      document.getElementById('pfTelefono').value.trim(),
    correo:        document.getElementById('pfCorreo').value.trim(),
    propietario:   document.getElementById('pfPropietario').value.trim(),
    tipoUso:       document.querySelector('input[name="pfTipoUso"]:checked')?.value || '',
    presentacion:  document.querySelector('input[name="pfPresentacion"]:checked')?.value || '',
    sistemaOp:     document.querySelector('input[name="pfSistemaOp"]:checked')?.value || '',
    fuenteAbast:   document.getElementById('pfFuenteAbast').value.trim(),
    largo:         parseFloat(document.getElementById('pfLargo').value) || null,
    ancho:         parseFloat(document.getElementById('pfAncho').value) || null,
    profMin:       parseFloat(document.getElementById('pfProfMin').value) || null,
    profMax:       parseFloat(document.getElementById('pfProfMax').value) || null,
    volumen:       parseFloat(document.getElementById('pfVolVal')?.textContent) || null,
    aforo:         parseInt(document.getElementById('pfAforo').value) || null,
    opNombre:      document.getElementById('pfOpNombre').value.trim(),
    opNit:         document.getElementById('pfOpNit').value.trim(),
    opTel:         document.getElementById('pfOpTel').value.trim(),
    salvavidas:    _readSalvavidasForm(),
  };
  localStorage.setItem(PERFIL_KEY, JSON.stringify(p));
  _syncPerfilToReporte(p);
  showToast('Perfil guardado correctamente.', 'success');
}

function _syncPerfilToReporte(p) {
  const data = JSON.parse(localStorage.getItem('aqua_reporte') || '{}');
  if (p.razonSocial) data.repNombre      = p.razonSocial;
  if (p.propietario) data.repResponsable = p.propietario;
  if (p.municipio)   data.repUbicacion   = [p.municipio, p.departamento].filter(Boolean).join(', ');
  if (p.volumen)     data.repVolumen     = p.volumen.toFixed(1);
  localStorage.setItem('aqua_reporte', JSON.stringify(data));
}

function renderPerfil() {
  const p = getPerfil();
  const set = (id, val) => { const el = document.getElementById(id); if (el && val != null) el.value = val; };
  set('pfRazonSocial', p.razonSocial);
  set('pfMatricula',   p.matricula);
  set('pfNit',         p.nit);
  set('pfDireccion',   p.direccion);
  set('pfMunicipio',   p.municipio);
  set('pfDepartamento',p.departamento);
  set('pfTelefono',    p.telefono);
  set('pfCorreo',      p.correo);
  set('pfPropietario', p.propietario);
  set('pfFuenteAbast', p.fuenteAbast);
  set('pfLargo',       p.largo);
  set('pfAncho',       p.ancho);
  set('pfProfMin',     p.profMin);
  set('pfProfMax',     p.profMax);
  set('pfAforo',       p.aforo);
  set('pfOpNombre',    p.opNombre);
  set('pfOpNit',       p.opNit);
  set('pfOpTel',       p.opTel);
  if (p.tipoUso)      { const r = document.querySelector(`input[name="pfTipoUso"][value="${p.tipoUso}"]`);      if (r) r.checked = true; }
  if (p.presentacion) { const r = document.querySelector(`input[name="pfPresentacion"][value="${p.presentacion}"]`); if (r) r.checked = true; }
  if (p.sistemaOp)    { const r = document.querySelector(`input[name="pfSistemaOp"][value="${p.sistemaOp}"]`);  if (r) r.checked = true; }
  calcPerfilVolumen();
  _renderSalvavidasList(p.salvavidas || []);
}

function calcPerfilVolumen() {
  const l  = parseFloat(document.getElementById('pfLargo').value);
  const a  = parseFloat(document.getElementById('pfAncho').value);
  const p1 = parseFloat(document.getElementById('pfProfMin').value);
  const p2 = parseFloat(document.getElementById('pfProfMax').value);
  const res  = document.getElementById('pfVolResult');
  const val  = document.getElementById('pfVolVal');
  if (!isFinite(l) || !isFinite(a) || !isFinite(p1) || !isFinite(p2)) {
    if (res) res.hidden = true; return;
  }
  const vol = l * a * ((p1 + p2) / 2);
  if (val) val.textContent = vol.toFixed(2) + ' m³';
  const perimEl = document.getElementById('pfPerimVal');
  if (perimEl) perimEl.textContent = (2 * (l + a)).toFixed(2) + ' m';
  if (res) res.hidden = false;
  const sug = document.getElementById('pfAforoSug');
  if (sug) {
    const sugerido = Math.floor(l * a / 2.5);
    sug.textContent = `Norma sugiere ≈ ${sugerido} personas (1 c/2.5 m²)`;
  }
}

// ── Gestión de salvavidas ──────────────────────────────────
let _salvavidasArr = [];

function _readSalvavidasForm() {
  return _salvavidasArr.map((_, i) => ({
    nombre: (document.getElementById(`sv_nombre_${i}`)?.value || '').trim(),
    nia:    (document.getElementById(`sv_nia_${i}`)?.value    || '').trim(),
  })).filter(s => s.nombre || s.nia);
}

function _renderSalvavidasList(arr) {
  _salvavidasArr = arr.length ? arr.map(s => ({ ...s })) : [];
  _paintSalvavidasList();
}

function addSalvavidas() {
  _salvavidasArr.push({ nombre: '', nia: '' });
  _paintSalvavidasList();
  setTimeout(() => document.getElementById(`sv_nombre_${_salvavidasArr.length - 1}`)?.focus(), 50);
}

function removeSalvavidas(idx) {
  _salvavidasArr.splice(idx, 1);
  _paintSalvavidasList();
}

function _paintSalvavidasList() {
  const el = document.getElementById('pfSalvavidasList');
  if (!el) return;
  if (!_salvavidasArr.length) {
    el.innerHTML = '<p class="perfil-hint u-mb10">Sin salvavidas registrados.</p>';
    return;
  }
  el.innerHTML = _salvavidasArr.map((s, i) => `
    <div class="perfil-sv-row">
      <div class="form-group fg-2">
        <label class="form-label" for="sv_nombre_${i}">NOMBRE COMPLETO</label>
        <input type="text" class="form-input" id="sv_nombre_${i}" value="${escapeHtml(s.nombre)}" placeholder="Nombre del salvavidas" maxlength="100" />
      </div>
      <div class="form-group fg-1">
        <label class="form-label" for="sv_nia_${i}">N.º IDENTIFICACIÓN ACUÁTICA (NIA)</label>
        <input type="text" class="form-input" id="sv_nia_${i}" value="${escapeHtml(s.nia)}" placeholder="Ej. NIA-2024-00123" maxlength="40" />
      </div>
      <button type="button" class="btn-delete-log perfil-sv-del" data-sv-idx="${i}" title="Eliminar salvavidas">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
      </button>
    </div>`).join('');
}

// ── VISITAS DE INSPECCIÓN SANITARIA ──────────────────────
function _isValidVisita(v) {
  return v !== null && typeof v === 'object'
    && typeof v.ts          === 'number' && isFinite(v.ts)
    && typeof v.fecha       === 'string' && v.fecha.length > 0
    && typeof v.funcionario === 'string' && v.funcionario.length > 0
    && ['favorable', 'requerimientos', 'desfavorable'].includes(v.concepto);
}

function _visitasRaw() {
  try {
    const raw = JSON.parse(localStorage.getItem('aqua_visitas') || '[]');
    return Array.isArray(raw) ? raw.filter(_isValidVisita) : [];
  } catch { return []; }
}

function getVisitas() {
  if (!_requireUnlocked()) return [];
  return _visitasRaw();
}

let _editingVisitaTs = null;

function onVisitaConceptoChange() {
  const val = document.querySelector('input[name="visitaConcepto"]:checked')?.value;
  const wrap = document.getElementById('visitaObsWrap');
  if (wrap) wrap.hidden = (val === 'favorable' || !val);
  ['vcOptFav','vcOptReq','vcOptDes'].forEach(id => document.getElementById(id)?.classList.remove('vc-selected'));
  const map = { favorable: 'vcOptFav', requerimientos: 'vcOptReq', desfavorable: 'vcOptDes' };
  if (val && map[val]) document.getElementById(map[val])?.classList.add('vc-selected');
}

function clearVisitaForm() {
  const now = new Date();
  document.getElementById('visitaFecha').value       = localDateStr(now);
  document.getElementById('visitaHora').value        = now.toTimeString().slice(0,5);
  document.getElementById('visitaFuncionario').value = '';
  document.getElementById('visitaEntidad').value     = '';
  document.querySelectorAll('input[name="visitaConcepto"]').forEach(r => r.checked = false);
  ['vcOptFav','vcOptReq','vcOptDes'].forEach(id => document.getElementById(id)?.classList.remove('vc-selected'));
  document.getElementById('visitaObsWrap').hidden    = true;
  document.getElementById('visitaObs').value         = '';
  document.getElementById('visitaPlazo').value       = '';
  _editingVisitaTs = null;
  document.getElementById('visitaEditBanner').style.display = 'none';
  document.getElementById('btnCancelVisita').style.display  = 'none';
  document.getElementById('btnSaveVisita').textContent = ' Registrar visita';
}

function saveVisita() {
  if (!_requireUnlocked()) return;
  const fecha       = document.getElementById('visitaFecha').value;
  const funcionario = document.getElementById('visitaFuncionario').value.trim();
  const concepto    = document.querySelector('input[name="visitaConcepto"]:checked')?.value;
  if (!fecha || !funcionario || !concepto) {
    showToast('Completa fecha, funcionario y concepto.', 'warning'); return;
  }
  const entry = {
    ts:          _editingVisitaTs || Date.now(),
    fecha,
    hora:        document.getElementById('visitaHora').value,
    funcionario,
    entidad:     document.getElementById('visitaEntidad').value.trim(),
    concepto,
    obs:         concepto !== 'favorable' ? document.getElementById('visitaObs').value.trim() : '',
    plazo:       concepto !== 'favorable' ? document.getElementById('visitaPlazo').value : '',
  };
  const list = _visitasRaw().filter(v => v.ts !== entry.ts);
  list.unshift(entry);
  list.sort((a, b) => new Date(b.fecha) - new Date(a.fecha));
  _secSave('aqua_visitas', JSON.stringify(list));

  // Sincroniza el concepto estático de Documentos con la última visita
  const dates = JSON.parse(localStorage.getItem('aqua_docs_dates') || '{}');
  dates['concepto'] = concepto === 'favorable' ? 'verde' : concepto === 'requerimientos' ? 'amarillo' : 'rojo';
  localStorage.setItem('aqua_docs_dates', JSON.stringify(dates));

  clearVisitaForm();
  renderVisitas();
  renderDashboardVencimientos();
  showToast('Visita registrada correctamente.', 'success');
}

function editVisita(ts) {
  if (!_requireUnlocked()) return;
  const v = _visitasRaw().find(x => x.ts === ts);
  if (!v) return;
  _editingVisitaTs = ts;
  document.getElementById('visitaFecha').value       = v.fecha;
  document.getElementById('visitaHora').value        = v.hora || '';
  document.getElementById('visitaFuncionario').value = v.funcionario;
  document.getElementById('visitaEntidad').value     = v.entidad || '';
  const radio = document.querySelector(`input[name="visitaConcepto"][value="${v.concepto}"]`);
  if (radio) { radio.checked = true; onVisitaConceptoChange(); }
  document.getElementById('visitaObs').value   = v.obs   || '';
  document.getElementById('visitaPlazo').value = v.plazo || '';
  document.getElementById('visitaEditBanner').style.display = 'flex';
  document.getElementById('visitaEditDate').textContent     = v.fecha;
  document.getElementById('btnCancelVisita').style.display  = 'inline-flex';
  document.getElementById('btnSaveVisita').textContent = ' Actualizar visita';
  document.getElementById('cardVisitas').scrollIntoView({ behavior: 'smooth' });
}

function deleteVisita(ts) {
  if (!_requireUnlocked()) return;
  if (!confirm('¿Eliminar este registro de visita?')) return;
  const list = _visitasRaw().filter(v => v.ts !== ts);
  _secSave('aqua_visitas', JSON.stringify(list));
  renderVisitas();
  renderDashboardVencimientos();
  showToast('Visita eliminada.', 'success');
}

function viewVisita(ts) {
  const v = _visitasRaw().find(x => x.ts === ts);
  if (!v) return;

  const overlay = document.getElementById('visitaDetailOverlay');
  const title   = document.getElementById('visitaDetailTitle');
  const meta    = document.getElementById('visitaDetailMeta');
  const body    = document.getElementById('visitaDetailBody');

  title.textContent = `Visita del ${v.fecha}`;
  meta.textContent  = [v.hora || null, v.funcionario, v.entidad || null].filter(Boolean).join(' · ');

  const CONCEPTO_CFG = {
    favorable:      { label: 'Favorable',         cls: 'apt-det-ok',  icon: '✓' },
    requerimientos: { label: 'Con requerimientos', cls: 'apt-det-warn', icon: '⚠' },
    desfavorable:   { label: 'Desfavorable',       cls: 'apt-det-nok', icon: '✗' },
  };
  const cfg = CONCEPTO_CFG[v.concepto] || { label: v.concepto, cls: '', icon: '?' };

  const plazoHTML = v.plazo ? (() => {
    const days = Math.ceil((new Date(v.plazo + 'T00:00:00') - new Date()) / 86400000);
    const cls  = days < 0 ? 'visita-plazo-venc' : days <= 7 ? 'visita-plazo-warn' : 'visita-plazo-ok';
    const txt  = days < 0 ? `Plazo vencido · ${v.plazo}` : `Plazo: ${v.plazo} · quedan ${days} día${days === 1 ? '' : 's'}`;
    return `<div class="log-detail-extra-row"><span>Plazo de cumplimiento</span><span class="visita-plazo ${cls}">${txt}</span></div>`;
  })() : '';

  body.innerHTML = `
    <div class="apt-detail-banner ${cfg.cls}">
      <span class="apt-det-icon">${cfg.icon}</span>
      <strong>Concepto ${cfg.label}</strong>
    </div>

    <div class="log-detail-section">
      <div class="log-detail-section-title">Datos de la visita</div>
      <div class="log-detail-extra-row"><span>Fecha</span><strong>${escapeHtml(v.fecha)}</strong></div>
      ${v.hora ? `<div class="log-detail-extra-row"><span>Hora</span><strong>${escapeHtml(v.hora)}</strong></div>` : ''}
      <div class="log-detail-extra-row"><span>Funcionario</span><strong>${escapeHtml(v.funcionario)}</strong></div>
      ${v.entidad ? `<div class="log-detail-extra-row"><span>Entidad</span><strong>${escapeHtml(v.entidad)}</strong></div>` : ''}
    </div>

    ${v.obs || v.plazo ? `
    <div class="log-detail-section">
      <div class="log-detail-section-title">Requerimientos</div>
      ${v.obs ? `<div class="visita-obs u-mb10">${escapeHtml(v.obs)}</div>` : ''}
      ${plazoHTML}
    </div>` : ''}

    <div class="detail-actions">
      <button class="btn btn-outline btn-danger-outline btn-flex"
        onclick="deleteVisita(${v.ts}); document.getElementById('visitaDetailOverlay').classList.add('js-hidden')">
        <svg class="btn-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
        Eliminar
      </button>
      <button class="btn btn-outline btn-flex"
        onclick="editVisita(${v.ts}); document.getElementById('visitaDetailOverlay').classList.add('js-hidden')">
        <svg class="btn-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        Editar
      </button>
    </div>
  `;

  overlay.classList.remove('js-hidden');
}

function renderVisitas() {
  const el = document.getElementById('visitasHistory');
  if (!el) return;
  const list = _visitasRaw();
  if (!list.length) { el.innerHTML = '<p class="empty-state">Sin visitas registradas aún.</p>'; return; }

  const CONCEPTO_CFG = {
    favorable:      { label: 'Favorable',         cls: 'vc-badge-ok',   icon: '✓' },
    requerimientos: { label: 'Con requerimientos', cls: 'vc-badge-warn', icon: '⚠' },
    desfavorable:   { label: 'Desfavorable',       cls: 'vc-badge-nok',  icon: '✗' },
  };

  el.innerHTML = list.map(v => {
    const cfg = CONCEPTO_CFG[v.concepto] || { label: v.concepto, cls: '', icon: '?' };
    const plazoHTML = v.plazo
      ? (() => {
          const days = Math.ceil((new Date(v.plazo + 'T00:00:00') - new Date()) / 86400000);
          const cls  = days < 0 ? 'visita-plazo-venc' : days <= 7 ? 'visita-plazo-warn' : 'visita-plazo-ok';
          const txt  = days < 0 ? `Plazo vencido (${v.plazo})` : `Plazo: ${v.plazo} (${days}d)`;
          return `<span class="visita-plazo ${cls}">${txt}</span>`;
        })()
      : '';
    return `
    <div class="visita-item ${v.concepto === 'desfavorable' ? 'visita-item-nok' : v.concepto === 'requerimientos' ? 'visita-item-warn' : ''}" data-ts="${v.ts}" title="Ver ficha de la visita">
      <div class="visita-item-top">
        <div class="visita-item-info">
          <span class="visita-fecha">${escapeHtml(v.fecha)}${v.hora ? ' · ' + escapeHtml(v.hora) : ''}</span>
          <span class="vc-badge ${cfg.cls}">${cfg.icon} ${cfg.label}</span>
          ${plazoHTML}
        </div>
        <div class="visita-item-actions">
          <button class="btn-edit-log visita-edit-btn" data-ts="${v.ts}" title="Editar">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          </button>
          <button class="btn-delete-log visita-del-btn" data-ts="${v.ts}" title="Eliminar">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
          </button>
        </div>
      </div>
      <div class="visita-item-body">
        <span class="visita-func">👤 ${escapeHtml(v.funcionario)}${v.entidad ? ' · ' + escapeHtml(v.entidad) : ''}</span>
        ${v.obs ? `<p class="visita-obs">${escapeHtml(v.obs)}</p>` : ''}
      </div>
    </div>`;
  }).join('');
}

// ── BOTIQUÍN Y DEA ────────────────────────────────────────
const _BOT_A = [
  { id: 'guantes',        label: 'Guantes desechables (mín. 2 pares)' },
  { id: 'vendas_gasa',    label: 'Vendas de gasa estéril (mín. 3)' },
  { id: 'venda_elastica', label: 'Venda elástica' },
  { id: 'esparadrapo',    label: 'Esparadrapo / cinta médica' },
  { id: 'antiseptico',    label: 'Antiséptico (yodopovidona o equivalente)' },
  { id: 'tijeras',        label: 'Tijeras de punta roma' },
  { id: 'apositos',       label: 'Apósitos estériles surtidos' },
  { id: 'manual_pa',      label: 'Manual de primeros auxilios' },
];
const _BOT_B_EXTRA = [
  { id: 'colarin',       label: 'Collarín cervical (adulto y pediátrico)' },
  { id: 'ferulas',       label: 'Férulas de inmovilización' },
  { id: 'mascara_rcp',   label: 'Mascarilla barrera para RCP' },
  { id: 'oximetro',      label: 'Oxímetro de pulso' },
  { id: 'linterna',      label: 'Linterna con pilas de repuesto' },
];
const _BOT_C_EXTRA = [
  { id: 'dea_item',       label: 'DEA operativo, visible y señalizado' },
  { id: 'oxigeno_port',   label: 'Oxígeno portátil con mascarilla' },
  { id: 'manta_termica',  label: 'Manta térmica de emergencia' },
  { id: 'tabla_espinal',  label: 'Camilla rígida / tabla espinal' },
  { id: 'kit_trauma',     label: 'Kit de trauma avanzado' },
];
const BOTIQUIN_ITEMS = {
  A: _BOT_A,
  B: [..._BOT_A, ..._BOT_B_EXTRA],
  C: [..._BOT_A, ..._BOT_B_EXTRA, ..._BOT_C_EXTRA],
};
const BOTIQUIN_TIPO_DESC = {
  A: 'Piscinas pequeñas o de uso doméstico/familiar.',
  B: 'Establecimientos medianos o semipúblicos (conjuntos, clubes pequeños).',
  C: 'Piscinas públicas de alta afluencia — DEA obligatorio.',
};
let _botTipoActual = 'A';

function getBotiquin() {
  try { return JSON.parse(localStorage.getItem('aqua_botiquin') || '{}'); } catch { return {}; }
}

function _setBotiquinTipo(tipo) {
  _botTipoActual = tipo;
  ['A','B','C'].forEach(t => {
    const btn = document.getElementById('btnBot' + t);
    if (btn) btn.classList.toggle('active', t === tipo);
  });
  const deaSec = document.getElementById('botiquinDeaSection');
  if (deaSec) deaSec.hidden = tipo !== 'C';
  _renderBotiquinChecklist(tipo);
}

function _renderBotiquinChecklist(tipo) {
  const el = document.getElementById('botiquinChecklist');
  if (!el) return;
  const data = getBotiquin();
  const items = BOTIQUIN_ITEMS[tipo] || BOTIQUIN_ITEMS.A;
  const checked = data.items || {};
  el.innerHTML = items.map(item => `
    <label class="botiquin-check-item">
      <input type="checkbox" class="botiquin-checkbox" data-bot-item="${item.id}"
             ${checked[item.id] ? 'checked' : ''} />
      <span>${item.label}</span>
    </label>`).join('');
}

function _updateBotiquinDates() {
  const fechaEl    = document.getElementById('fechaBotiquin');
  const deaMantEl  = document.getElementById('fechaDeaMant');
  const deaElecEl  = document.getElementById('fechaDeaElectrodos');
  const statusEl   = document.getElementById('statusBotiquin');
  const mantStEl   = document.getElementById('statusDeaMant');
  const elecStEl   = document.getElementById('statusDeaElectrodos');
  const badgeEl    = document.getElementById('botiquinBadge');

  function _dayStatus(dateStr, statusTarget, warnDays, dangerDays) {
    if (!statusTarget) return;
    if (!dateStr) { statusTarget.textContent = '–'; statusTarget.className = 'docs-venc-status'; return; }
    const days = Math.ceil((new Date(dateStr + 'T00:00:00') - new Date()) / 86400000);
    if (days < 0)              { statusTarget.textContent = 'Vencido';    statusTarget.className = 'docs-venc-status status-danger'; }
    else if (days <= dangerDays){ statusTarget.textContent = `${days}d`;  statusTarget.className = 'docs-venc-status status-danger'; }
    else if (days <= warnDays)  { statusTarget.textContent = `${days}d`;  statusTarget.className = 'docs-venc-status status-warning'; }
    else                        { statusTarget.textContent = 'Vigente';   statusTarget.className = 'docs-venc-status status-ok'; }
  }

  // Verificación del botiquín: alertar si han pasado > 30 días desde la última
  if (fechaEl && statusEl) {
    if (!fechaEl.value) { statusEl.textContent = '–'; statusEl.className = 'docs-venc-status'; }
    else {
      const daysSince = Math.floor((Date.now() - new Date(fechaEl.value + 'T00:00:00')) / 86400000);
      if (daysSince > 30)      { statusEl.textContent = `Hace ${daysSince}d`; statusEl.className = 'docs-venc-status status-danger'; }
      else if (daysSince > 20) { statusEl.textContent = `Hace ${daysSince}d`; statusEl.className = 'docs-venc-status status-warning'; }
      else                     { statusEl.textContent = 'Al día';             statusEl.className = 'docs-venc-status status-ok'; }
    }
  }

  if (deaMantEl?.value) {
    const lastMant = new Date(deaMantEl.value + 'T00:00:00');
    const expiry   = new Date(lastMant);
    expiry.setFullYear(expiry.getFullYear() + 1);
    _dayStatus(expiry.toISOString().split('T')[0], mantStEl, 90, 30);
  } else {
    _dayStatus(null, mantStEl, 90, 30);
  }
  _dayStatus(deaElecEl?.value,  elecStEl,  30, 10);

  // Badge del header
  if (badgeEl) {
    const fecha = fechaEl?.value;
    if (!fecha) { badgeEl.textContent = 'Sin verificar'; badgeEl.className = 'botiquin-status-badge bot-badge-warn'; badgeEl.hidden = false; }
    else {
      const ds = Math.floor((Date.now() - new Date(fecha + 'T00:00:00')) / 86400000);
      if (ds > 30)      { badgeEl.textContent = 'Vencido'; badgeEl.className = 'botiquin-status-badge bot-badge-danger'; badgeEl.hidden = false; }
      else if (ds > 20) { badgeEl.textContent = `Hace ${ds}d`; badgeEl.className = 'botiquin-status-badge bot-badge-warn'; badgeEl.hidden = false; }
      else              { badgeEl.textContent = 'Al día'; badgeEl.className = 'botiquin-status-badge bot-badge-ok'; badgeEl.hidden = false; }
    }
  }
}

function saveBotiquin() {
  if (!_requireUnlocked()) return;
  const data = getBotiquin();
  data.tipo             = _botTipoActual;
  data.fechaVerificacion = document.getElementById('fechaBotiquin')?.value || null;
  data.fechaDeaMant     = document.getElementById('fechaDeaMant')?.value   || null;
  data.fechaDeaElectrodos = document.getElementById('fechaDeaElectrodos')?.value || null;

  const items = {};
  document.querySelectorAll('.botiquin-checkbox').forEach(cb => {
    items[cb.dataset.botItem] = cb.checked;
  });
  data.items = items;

  localStorage.setItem('aqua_botiquin', JSON.stringify(data));
  _updateBotiquinDates();
  renderDashboardVencimientos();
  showToast('Verificación de botiquín guardada.', 'success');
}

function renderBotiquinCard() {
  const data = getBotiquin();
  const tipo = data.tipo || 'A';
  _botTipoActual = tipo;

  ['A','B','C'].forEach(t => {
    const btn = document.getElementById('btnBot' + t);
    if (btn) btn.classList.toggle('active', t === tipo);
  });

  const deaSec = document.getElementById('botiquinDeaSection');
  if (deaSec) deaSec.hidden = tipo !== 'C';

  const fechaEl = document.getElementById('fechaBotiquin');
  if (fechaEl && data.fechaVerificacion) fechaEl.value = data.fechaVerificacion;
  const deaMantEl = document.getElementById('fechaDeaMant');
  if (deaMantEl && data.fechaDeaMant) deaMantEl.value = data.fechaDeaMant;
  const deaElecEl = document.getElementById('fechaDeaElectrodos');
  if (deaElecEl && data.fechaDeaElectrodos) deaElecEl.value = data.fechaDeaElectrodos;

  _renderBotiquinChecklist(tipo);
  _updateBotiquinDates();
}

// ── REGISTRO DE LABORATORIO TRIMESTRAL ────────────────────
const LAB_MICRO_KEYS = ['coliformesTotales', 'eColi', 'pseudomonas', 'staphylococcus'];
const LAB_MICRO_LABELS = {
  coliformesTotales: 'Coliformes totales',
  eColi: 'E. coli',
  pseudomonas: 'Pseudomonas aeruginosa',
  staphylococcus: 'Staphylococcus aureus',
};

function getLabRecords() {
  try { return JSON.parse(localStorage.getItem('aqua_lab') || '[]'); } catch { return []; }
}

function _labPctMicro(entry) {
  const tested = LAB_MICRO_KEYS.filter(k => entry[k] === 'ausente' || entry[k] === 'presente');
  if (!tested.length) return null;
  const nonConform = tested.filter(k => entry[k] === 'presente').length;
  return Math.round((nonConform / tested.length) * 100);
}

function _labDaysSince(entry) {
  if (!entry?.fecha) return null;
  return Math.floor((Date.now() - new Date(entry.fecha + 'T00:00:00').getTime()) / 86400000);
}

function saveLabRecord() {
  if (!_requireUnlocked()) return;
  const fecha        = document.getElementById('labFecha').value;
  const laboratorio  = document.getElementById('labLaboratorio').value.trim();
  const acreditacion = document.getElementById('labAcreditacion').value.trim();
  const coliformes   = document.getElementById('labColiformes').value;
  const ecoli        = document.getElementById('labEcoli').value;
  const pseudomonas  = document.getElementById('labPseudomonas').value;
  const staph        = document.getElementById('labStaph').value;
  const cyaRaw       = parseFloat(document.getElementById('labCya').value);

  if (!fecha)       { showToast('Ingresa la fecha de toma de muestra.', 'warning'); return; }
  if (!laboratorio) { showToast('Ingresa el nombre del laboratorio.', 'warning'); return; }
  const microFilled = [coliformes, ecoli, pseudomonas, staph].filter(v => v !== '');
  if (!microFilled.length) { showToast('Ingresa al menos un resultado microbiológico.', 'warning'); return; }

  const entry = {
    ts: Date.now(),
    fecha,
    laboratorio,
    acreditacion: acreditacion || null,
    coliformesTotales: coliformes || null,
    eColi:             ecoli      || null,
    pseudomonas:       pseudomonas || null,
    staphylococcus:    staph      || null,
    cya: isNaN(cyaRaw) ? null : cyaRaw,
  };

  const records = getLabRecords();
  records.unshift(entry);
  _secSave('aqua_lab', JSON.stringify(records));

  // Auto-actualizar slider microbiológico del IRAPI
  const pct = _labPctMicro(entry);
  if (pct !== null) {
    const sliderMicro = document.getElementById('sliderMicro');
    const microInput  = document.getElementById('microLabValue');
    if (sliderMicro) { sliderMicro.value = pct; }
    if (microInput)  { microInput.value  = pct; }
    calcIRAPI();
    showToast(`Resultado guardado. IRAPI microbiológico actualizado a ${pct}%.`, 'success');
  } else {
    showToast('Resultado de laboratorio guardado.', 'success');
  }

  // Limpiar formulario
  ['labFecha','labLaboratorio','labAcreditacion','labCya'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });
  ['labColiformes','labEcoli','labPseudomonas','labStaph'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });

  renderLabReg();
  renderDashboardVencimientos();
}

function deleteLabRecord(ts) {
  if (!_requireUnlocked()) return;
  showConfirm('¿Eliminar este resultado de laboratorio?', () => {
    const records = getLabRecords().filter(r => r.ts !== ts);
    _secSave('aqua_lab', JSON.stringify(records));
    renderLabReg();
    renderDashboardVencimientos();
    showToast('Registro eliminado.', 'success');
  });
}

function renderLabReg() {
  const records  = getLabRecords();
  const latest   = records[0] || null;
  const daysSince = _labDaysSince(latest);

  const alertEl  = document.getElementById('labRegAlert');
  const badgeEl  = document.getElementById('labRegBadge');
  const histEl   = document.getElementById('labRegHistory');
  if (!alertEl || !histEl) return;

  // Alert de vencimiento
  if (daysSince === null) {
    alertEl.hidden = false;
    alertEl.className = 'lab-reg-alert lab-reg-alert-warn';
    alertEl.innerHTML = '<svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> Sin análisis registrado. La Res. 234/2026 exige análisis microbiológico certificado cada 90 días.';
    if (badgeEl) { badgeEl.textContent = 'Sin registro'; badgeEl.className = 'lab-reg-badge lab-reg-badge-warn'; badgeEl.hidden = false; }
  } else if (daysSince > 90) {
    alertEl.hidden = false;
    alertEl.className = 'lab-reg-alert lab-reg-alert-danger';
    alertEl.innerHTML = `<svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> <strong>ANÁLISIS VENCIDO</strong> — Hace ${daysSince} días (límite: 90 días). Solicite un nuevo análisis a un laboratorio acreditado.`;
    if (badgeEl) { badgeEl.textContent = 'VENCIDO'; badgeEl.className = 'lab-reg-badge lab-reg-badge-danger'; badgeEl.hidden = false; }
  } else if (daysSince > 75) {
    alertEl.hidden = false;
    alertEl.className = 'lab-reg-alert lab-reg-alert-warn';
    alertEl.innerHTML = `<svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> Próximo vencimiento — quedan <strong>${90 - daysSince} días</strong> para el siguiente análisis trimestral.`;
    if (badgeEl) { badgeEl.textContent = `Vence en ${90 - daysSince}d`; badgeEl.className = 'lab-reg-badge lab-reg-badge-warn'; badgeEl.hidden = false; }
  } else {
    alertEl.hidden = true;
    if (badgeEl) { badgeEl.textContent = 'Vigente'; badgeEl.className = 'lab-reg-badge lab-reg-badge-ok'; badgeEl.hidden = false; }
  }

  // Historial
  if (!records.length) {
    histEl.innerHTML = '<p class="empty-state">Sin análisis registrados.</p>';
    return;
  }

  histEl.innerHTML = records.map(r => {
    const pct  = _labPctMicro(r);
    const cya  = r.cya != null ? `${r.cya} mg/L` : '–';
    const cyaOut = r.cya != null && r.cya > 15;
    const microRows = LAB_MICRO_KEYS
      .filter(k => r[k])
      .map(k => {
        const ok = r[k] === 'ausente';
        return `<span class="lab-micro-chip ${ok ? 'lab-chip-ok' : 'lab-chip-out'}">${LAB_MICRO_LABELS[k]}: ${ok ? '✓ Ausente' : '✗ Presente'}</span>`;
      }).join('');
    return `
    <div class="lab-reg-item" data-ts="${r.ts}">
      <div class="lab-reg-item-header">
        <strong>${escapeHtml(r.fecha || '–')}</strong>
        <span class="lab-reg-item-lab">${escapeHtml(r.laboratorio || '–')}${r.acreditacion ? ` · ${escapeHtml(r.acreditacion)}` : ''}</span>
        ${pct !== null ? `<span class="lsi-pbadge ${pct === 0 ? 'lsi-pbadge-ok' : 'lsi-pbadge-out'} u-ml-auto">Micro: ${pct}% NC</span>` : ''}
        <button class="btn-delete-lab" data-ts="${r.ts}" title="Eliminar registro" aria-label="Eliminar registro">
          <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
        </button>
      </div>
      ${microRows ? `<div class="lab-micro-chips">${microRows}</div>` : ''}
      ${r.cya != null ? `<div class="lab-cya-row">CYA (lab): <strong class="${cyaOut ? 'text-danger' : ''}">${cya}</strong>${cyaOut ? ' ⚠ Sobre límite' : ''}</div>` : ''}
    </div>`;
  }).join('');
}

function renderVencSaneamiento() {
  const el = document.getElementById('vencSaneamientoList');
  if (!el) return;

  const today   = Date.now();
  const mntRaw  = _mntLogRaw();
  const labRecs = getLabRecords();

  const rows = [];

  SANEAMIENTO_PROGRAMS.forEach(prog => {
    const last = mntRaw.find(e => e.area === prog.id);
    if (!last) {
      rows.push({ label: prog.label, msg: 'Sin registro', cls: '' });
    } else {
      const ds = Math.floor((today - new Date(last.fecha + 'T00:00:00')) / 86400000);
      const pct = ds / prog.dias;
      if (pct >= 1)         rows.push({ label: prog.label, msg: 'Vencido',              cls: 'status-danger'  });
      else if (pct >= 0.7)  rows.push({ label: prog.label, msg: `${prog.dias - ds} días`, cls: 'status-warning' });
      else                  rows.push({ label: prog.label, msg: 'Al dia',                cls: 'status-ok'      });
    }
  });

  // Botiquin
  const botiquin = getBotiquin();
  if (!botiquin.fechaVerificacion) {
    rows.push({ label: 'Botiquin', msg: 'Sin verificar', cls: 'status-warning' });
  } else {
    const botDs = Math.floor((today - new Date(botiquin.fechaVerificacion + 'T00:00:00')) / 86400000);
    if (botDs > 30)      rows.push({ label: 'Botiquin', msg: 'Vencido',        cls: 'status-danger'  });
    else if (botDs > 20) rows.push({ label: 'Botiquin', msg: `Hace ${botDs}d`, cls: 'status-warning' });
    else                 rows.push({ label: 'Botiquin', msg: 'Al dia',          cls: 'status-ok'      });
  }

  // Lab trimestral
  const lastLab = labRecs.sort((a, b) => (b.fecha || '').localeCompare(a.fecha || ''))[0];
  if (!lastLab) {
    rows.push({ label: 'Lab. trimestral', msg: 'Sin registro', cls: '' });
  } else {
    const ds = Math.floor((today - new Date(lastLab.fecha + 'T00:00:00')) / 86400000);
    if (ds > 90)       rows.push({ label: 'Lab. trimestral', msg: 'Vencido',           cls: 'status-danger'  });
    else if (ds > 63)  rows.push({ label: 'Lab. trimestral', msg: `${90 - ds} dias`,   cls: 'status-warning' });
    else               rows.push({ label: 'Lab. trimestral', msg: 'Al dia',             cls: 'status-ok'      });
  }

  el.innerHTML = `
    <div class="docs-venc-san-title">Saneamiento y operacion</div>
    ${rows.map(r => `
      <div class="docs-venc-item">
        <span class="docs-venc-label">${r.label}</span>
        <span class="docs-venc-status ${r.cls}">${r.msg}</span>
      </div>`).join('')}`;
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

if ('serviceWorker' in navigator && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
  window.addEventListener('load', () => { navigator.serviceWorker.register('./sw.js').catch(() => {}); });
}

document.addEventListener('DOMContentLoaded', async () => {
  initOnboarding();              // Muestra pantalla de bienvenida solo en primer uso
  _pinInit();                    // Muestra overlay de PIN antes que cualquier otra cosa
  await _SECURE_STORE.init();    // Hidrata y protege los datos sensibles del cliente
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
    renderLabReg();
    renderBotiquinCard();
    renderSaneamiento();
    updateReportBtn();
    updateDashReportBtn();
    initDocs();
    restoreReportFields();
    ['sliderMicro','sliderCloro','sliderAlk','sliderOtros'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.setProperty('--pct', el.value + '%');
    });
  }, 0);

  const _isMobile = () => navigator.maxTouchPoints > 0 && /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      // Bloqueo automatico solo en movil — en PC es molesto al cambiar de pestana
      if (_isMobile() && _PIN.exists() && _PIN.unlocked && !_photoPickerActive) lockApp();
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
    && (e.area in MNT_AREA_LABELS)
    && typeof e.descripcion === 'string' && e.descripcion.length > 0;
}

// ── SANEAMIENTO BÁSICO ────────────────────────────────────
const SANEAMIENTO_PROGRAMS = [
  { id: 'san_limpieza',  label: 'Limpieza y desinfección',      frecLabel: 'Semanal',  dias: 7  },
  { id: 'san_vectores',  label: 'Control de vectores y plagas', frecLabel: 'Mensual',  dias: 30 },
  { id: 'san_residuos',  label: 'Gestión de residuos sólidos',  frecLabel: 'Semanal',  dias: 7  },
  { id: 'san_agua',      label: 'Suministro de agua potable',   frecLabel: 'Mensual',  dias: 30 },
  { id: 'san_aguas_res', label: 'Manejo de aguas residuales',   frecLabel: 'Mensual',  dias: 30 },
];

const MNT_AREA_LABELS = {
  motobomba:    { label: 'Motobomba',                   badge: 'mnt-badge-motobomba' },
  caldera:      { label: 'Caldera',                     badge: 'mnt-badge-caldera'   },
  san_limpieza: { label: 'Limpieza y desinfección',     badge: 'mnt-badge-san'       },
  san_vectores: { label: 'Control vectores y plagas',   badge: 'mnt-badge-san'       },
  san_residuos: { label: 'Residuos sólidos',            badge: 'mnt-badge-san'       },
  san_agua:     { label: 'Agua potable',                badge: 'mnt-badge-san'       },
  san_aguas_res:{ label: 'Aguas residuales',            badge: 'mnt-badge-san'       },
};

function _mntLogRaw() {
  try {
    const raw = JSON.parse(localStorage.getItem('aqua_mantenimiento') || '[]');
    return Array.isArray(raw) ? raw.filter(_isValidMntEntry) : [];
  } catch { return []; }
}

function _sanPreFill(areaId) {
  const el = document.getElementById('mntArea');
  if (el) { el.value = areaId; checkMntForm(); }
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function renderSaneamiento() {
  const el = document.getElementById('sanTracker');
  if (!el) return;
  const log = _mntLogRaw();
  const sanIds = new Set(SANEAMIENTO_PROGRAMS.map(p => p.id));
  const sanLog = log.filter(e => sanIds.has(e.area));

  // ── Semáforo por programa ──
  const trackerHTML = SANEAMIENTO_PROGRAMS.map(prog => {
    const last      = sanLog.find(e => e.area === prog.id);
    const warn      = Math.ceil(prog.dias * 0.3);
    let statusClass = 'san-status-none';
    let statusText  = 'Sin registro';
    let fechaText   = '–';

    if (last) {
      const daysSince = Math.floor((Date.now() - new Date(last.fecha + 'T00:00:00')) / 86400000);
      const daysLeft  = prog.dias - daysSince;
      fechaText = last.fecha;
      if (daysSince > prog.dias) { statusClass = 'san-status-danger'; statusText = `VENCIDO (hace ${daysSince}d)`; }
      else if (daysLeft <= warn)  { statusClass = 'san-status-warn';   statusText = `Vence en ${daysLeft}d`; }
      else                        { statusClass = 'san-status-ok';     statusText = `Al día (hace ${daysSince}d)`; }
    }

    return `
    <div class="san-item">
      <div class="san-item-left">
        <span class="san-item-label">${prog.label}</span>
        <span class="san-item-frec">${prog.frecLabel}</span>
      </div>
      <div class="san-item-right">
        <span class="san-item-fecha">${fechaText}</span>
        <span class="san-status ${statusClass}">${statusText}</span>
        <button class="san-reg-btn" data-san-id="${prog.id}" title="Registrar ${prog.label}">+</button>
      </div>
    </div>`;
  }).join('');

  // ── Historial de registros ──
  let histHTML = '<div class="san-hist-title">Historial de ejecuciones</div>';
  if (!sanLog.length) {
    histHTML += '<p class="empty-state">Sin registros aún. Usa el formulario de arriba.</p>';
  } else {
    histHTML += sanLog.map(e => {
      const areaInfo = MNT_AREA_LABELS[e.area] || { label: e.area, badge: 'mnt-badge-san' };
      return `
      <div class="san-hist-item" data-ts="${e.ts}">
        <div class="san-hist-info">
          <strong>${escapeHtml(e.fecha)}</strong>
          <span class="mnt-area-badge ${areaInfo.badge}">${escapeHtml(areaInfo.label)}</span>
          <span class="san-hist-tec">Técnico: ${escapeHtml(e.tecnico)}</span>
          <span class="san-hist-desc">${escapeHtml(e.descripcion)}</span>
        </div>
        <div class="san-hist-actions">
          <button class="btn-edit-log san-edit-btn" data-ts="${e.ts}" title="Editar">
            <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          </button>
          <button class="btn-delete-log san-del-btn" data-ts="${e.ts}" title="Eliminar">
            <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
          </button>
        </div>
      </div>`;
    }).join('');
  }

  el.innerHTML = trackerHTML + histHTML;
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

  const areaLabel = (MNT_AREA_LABELS[area] || { label: area }).label;
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
  renderSaneamiento();
  showToast(toastMsg, 'success');
}

function deleteMnt(ts) {
  if (!_requireUnlocked()) return;
  showConfirm('¿Eliminar este registro de mantenimiento? Esta acción no se puede deshacer.', () => {
    const log = getMntLog().filter(e => e.ts !== ts);
    _secSave('aqua_mantenimiento', JSON.stringify(log));
    renderMnt();
    renderSaneamiento();
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
    const areaInfo   = MNT_AREA_LABELS[e.area] || { label: e.area, badge: 'mnt-badge-caldera' };
    const badgeClass = areaInfo.badge;
    const badgeText  = areaInfo.label;
    const proxTxt    = e.proximo ? ` · Próximo: ${escapeHtml(e.proximo)}` : '';
    const hasPhoto   = !!_safePhotoSrc(e.foto);
    return `
    <div class="mnt-item" data-ts="${e.ts}" title="Ver detalle del mantenimiento">
      <div class="mnt-item-info">
        <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
        <div>
          <div class="mnt-hist-meta">
            <strong>${escapeHtml(e.fecha)}</strong>
            <span class="mnt-area-badge ${badgeClass}">${badgeText}</span>
            ${hasPhoto ? `<svg title="Foto adjunta" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>` : ''}
          </div>
          <span class="detail-meta">Técnico: ${escapeHtml(e.tecnico)}${proxTxt}</span>
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

  const areaInfo   = MNT_AREA_LABELS[e.area] || { label: e.area, badge: 'mnt-badge-caldera' };
  const badgeClass = areaInfo.badge;
  const badgeText  = areaInfo.label;

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
      <p class="detail-h3">${escapeHtml(e.tecnico)}</p>
    </div>
    <div class="log-detail-section">
      <div class="log-detail-section-title">Descripción del trabajo</div>
      <p class="detail-p">${escapeHtml(e.descripcion)}</p>
    </div>
    ${fotoHTML}
    <div class="detail-actions-wrap">
      <button class="btn btn-outline btn-danger-outline js-mnt-detail-delete btn-flex">
        <svg class="btn-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
        Eliminar
      </button>
      <button class="btn btn-outline js-mnt-detail-edit btn-flex">
        <svg class="btn-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        Editar
      </button>
      <button class="btn btn-primary js-mnt-detail-close btn-flex">Cerrar</button>
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
  if (!s1 || !s2) return;

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
    const fab = document.getElementById('jgFab');
    if (fab) fab.removeAttribute('hidden');
    if (section && section !== 'dashboard') navigate(section);
  }, 420);
}

let _jgPanelTimer = null;

function openJGPanel() {
  const panel = document.getElementById('jgPanel');
  if (!panel) return;
  clearTimeout(_jgPanelTimer);
  panel.removeAttribute('hidden');
  requestAnimationFrame(() => panel.classList.add('jg-panel--open'));
}

function closeJGPanel() {
  const panel = document.getElementById('jgPanel');
  if (!panel) return;
  panel.classList.remove('jg-panel--open');
  _jgPanelTimer = setTimeout(() => panel.setAttribute('hidden', ''), 280);
}

// ── ONBOARDING ────────────────────────────────────────────────
function initOnboarding() {
  if (localStorage.getItem('aqua_onboarded')) return;

  // Esperar a que el PIN se cierre (usuario autenticado) antes de mostrar el tutorial
  const pinOverlay = document.getElementById('pinOverlay');
  if (!pinOverlay) return;

  const observer = new MutationObserver(() => {
    if (pinOverlay.hidden) {
      observer.disconnect();
      _showOnboarding();
    }
  });
  observer.observe(pinOverlay, { attributes: true, attributeFilter: ['hidden'] });
}

function _showOnboarding() {
  if (localStorage.getItem('aqua_onboarded')) return;

  const overlay = document.getElementById('onboardingOverlay');
  if (!overlay) return;

  overlay.removeAttribute('hidden');

  // Evitar duplicar listeners si se llama más de una vez
  const fresh = overlay.cloneNode(true);
  overlay.replaceWith(fresh);

  function _obGo(from, to) {
    const fromEl = fresh.querySelector('#obStep' + from);
    const toEl   = fresh.querySelector('#obStep' + to);
    if (!fromEl || !toEl) return;
    fromEl.classList.add('ob-exit');
    setTimeout(() => {
      fromEl.classList.add('ob-hidden');
      fromEl.classList.remove('ob-exit');
      toEl.classList.remove('ob-hidden');
    }, 300);
  }

  function _obDismiss(section) {
    localStorage.setItem('aqua_onboarded', '1');
    fresh.style.transition = 'opacity 0.4s ease';
    fresh.style.opacity = '0';
    setTimeout(() => {
      fresh.setAttribute('hidden', '');
      fresh.style.opacity = '';
      if (section && section !== 'dashboard') navigate(section);
    }, 400);
  }

  fresh.addEventListener('click', e => {
    const t = e.target;
    if (t.closest('#obBtn1'))    { _obGo(1, 2);            return; }
    if (t.closest('#obSkip'))    { _obDismiss('dashboard'); return; }
    if (t.closest('#obBack2'))   { _obGo(2, 1);            return; }
    if (t.closest('#obBtn2'))    { _obGo(2, 3);            return; }
    if (t.closest('#obBack3'))   { _obGo(3, 2);            return; }
    if (t.closest('#obGoPerfil')){ _obDismiss('bitacora');  return; }
    if (t.closest('#obLater'))   { _obDismiss('dashboard'); return; }
  });
}

// ── EXPORTAR / IMPORTAR RESPALDO JSON ────────────────────────
function exportarBackupJSON() {
  const KEYS = ['aqua_bitacora', 'aqua_afr', 'aqua_mantenimiento', 'aqua_lab', 'aqua_perfil', 'aqua_config', 'aqua_visitas', 'aqua_reporte'];
  const backup = {
    _meta: { app: 'Aquatech', version: '2.0', fecha: new Date().toISOString(), registros: getLog().length },
    data: {}
  };
  KEYS.forEach(k => {
    try { const v = localStorage.getItem(k); if (v) backup.data[k] = JSON.parse(v); } catch {}
  });
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `Aquatech_backup_${localDateStr(new Date())}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`Respaldo exportado: ${backup._meta.registros} registros de bitácora.`, 'ok', 5000);
}

function importarBackupJSON(input) {
  const file = input.files[0];
  if (!file) return;
  input.value = '';
  const reader = new FileReader();
  reader.onload = e => {
    let backup;
    try { backup = JSON.parse(e.target.result); } catch { showToast('Archivo inválido — no es un JSON válido.', 'error'); return; }
    if (!backup._meta || !backup.data) { showToast('Formato de respaldo no reconocido.', 'error'); return; }
    const fecha = backup._meta.fecha ? backup._meta.fecha.slice(0, 10) : '?';
    const regs  = backup._meta.registros ?? '?';
    showConfirm(
      `¿Restaurar respaldo del ${fecha}?\n\nContiene ${regs} registros de bitácora. Los datos actuales serán reemplazados. Esta acción no se puede deshacer.`,
      async () => {
        for (const [k, v] of Object.entries(backup.data)) {
          await _secSave(k, JSON.stringify(v));
        }
        showToast('Respaldo restaurado correctamente. Recarga la app para ver todos los cambios.', 'ok', 7000);
      }
    );
  };
  reader.readAsText(file);
}

// ── EXPORTAR BITÁCORA CSV ─────────────────────────────────────
function exportarCSVBitacora() {
  const log = getReportLog();
  if (!log.length) { showToast('No hay registros para exportar.', 'warn'); return; }

  const HEADERS = [
    'Fecha','Hora','Momento','Operador','Salvavidas','NIA',
    'Cl.Libre(ppm)','Cl.Comb(ppm)','Bromo(ppm)','pH','Alc(ppm)','Dureza(ppm)','CYA(ppm)',
    'Turbidez(UNT)','T.Agua(°C)','T.Aire(°C)','Humedad(%)','ORP(mV)','TDS(ppm)','Conductividad(µS/cm)',
    'ISL','NivelAgua(m)','Bañistas',
    'HoraInicio','HoraFin','HorasFun(h)','HorasFilt(h)','Caudal(m3/h)','AguaRep(m3)',
    'Retrolavados','Presion(psi)','Neutralizador','CloroDos','HoraAjuste',
    'ProductosQuimicos','Averias',
    'Color','Flotantes','Olor','Transparencia',
    'Aptitud','MotivoNoApta',
    'Labores','Seguridad','Instalacion'
  ];

  const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;

  const rows = log.map(e => [
    e.fecha, e.hora, e.momento, e.operador, e.salvavidas, e.salvavidasNia,
    e.cloro, e.clorocomb, e.bromo, e.ph, e.alc, e.dureza, e.cya,
    e.turb, e.temp, e.tempAire, e.humedad, e.orp, e.tds, e.cond,
    e.isl, e.nivelAgua, e.banistas,
    e.horaInicio, e.horaFin, e.horasFun, e.horasFilt, e.caudal, e.aguaRep,
    e.retrolav, e.presion, e.neutralizador, e.cloroDos, e.horaAjuste,
    e.prodQuim, e.averias,
    e.fisColor, e.fisFlotantes, e.fisOlor, e.fisTransp,
    e.aptitud, e.motivoNoApta,
    e.labores   ? Object.entries(e.labores).filter(([,v])=>v).map(([k])=>k).join('|')    : '',
    e.seguridad ? Object.entries(e.seguridad).filter(([,v])=>v).map(([k])=>k).join('|') : '',
    e.instalacion ? Object.entries(e.instalacion).filter(([,v])=>v).map(([k])=>k).join('|') : '',
  ].map(esc).join(','));

  const csv  = [HEADERS.map(esc).join(','), ...rows].join('\r\n');
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `Aquatech_bitacora_${localDateStr(new Date())}.csv`;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`CSV exportado: ${log.length} registros.`, 'ok', 5000);
}

(function initPreloader() {
  setTimeout(() => {
    const dots = document.getElementById('preloaderDots');
    const btn  = document.getElementById('preloaderBtn');
    if (dots) dots.style.display = 'none';
    if (btn)  btn.style.display  = 'flex';
  }, 7000);
}());