'use strict';
const $ = id => document.getElementById(id);
let csrf = '', pairing = false, trustChallenge = '', refreshTimer;
let inspectionState = 'off', lastFlows = [], lastClients = [];
let selectedFlowId = null, selectedDetail = null, activeTab = 'response';
let viewMode = { request: 'auto', response: 'auto' };
let flowsPaused = false, pollBusy = false, filterSaveBusy = false;
let pendingExportUrl = null, pendingExportMeta = null, deepSearchMatchMap = null;
const INSPECTOR_CACHE_KEY = 'netbridge.inspector.cache.v1';
let flowDetailCache = new Map();

// Ephemeral RAM-key AES-256-GCM Encrypted Browser Archive (IndexedDB)
const ARCHIVE_DB_PREFIX = 'netbridge_archive_';
const ARCHIVE_LEGACY_DB = 'netbridge_ephemeral_archive_v1';
const ARCHIVE_WRITER_LOCK = 'netbridge-archive-writer-v1';
const ARCHIVE_STORE = 'details';
const ARCHIVE_SCHEMA_VERSION = 1;
const ARCHIVE_INACTIVITY_MS = 30 * 60 * 1000;
const ARCHIVE_WARN_REMAINING_MS = 5 * 60 * 1000;

let archiveEnabled = false;
let archivePausedReason = ''; // '', 'manual', 'limit', 'quota'
let archiveId = '';
let archiveDbName = '';
let archiveDb = null;
let archiveKey = null;
let archiveIvSalt = null;
let archiveIvCounter = 0;
let archiveWriterLock = null;
let archiveDbLock = null;
let archiveDeviceId = '';
let archiveCaFingerprint = '';
let archiveSessionId = '';
let archiveHighWaterId = 0;
let archiveSeq = 0;
let archiveCount = 0;
let archiveMissedCount = 0;
let archiveBytes = 0;
let archiveLimitBytes = 256 * 1024 * 1024;
let archiveSyncBusy = false;
let archiveExpiresAt = 0;
let archiveLastActivityTouch = 0;
let archiveOrphanPending = false;
let archiveNeedsRevalidation = false;
let archiveLastCaptureStats = null;
let archivedSummaries = new Map();
const authChannel = typeof BroadcastChannel === 'function' ? new BroadcastChannel('netbridge-auth-v1') : null;

function newRandomHex(bytes = 16) {
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}
function acquireExclusiveLock(name) {
  if (!navigator.locks || typeof navigator.locks.request !== 'function') {
    return Promise.resolve(null);
  }
  return new Promise(resolve => {
    navigator.locks.request(name, { mode: 'exclusive', ifAvailable: true }, lock => {
      if (!lock) {
        resolve(null);
        return;
      }
      return new Promise(release => {
        resolve({ release });
      });
    }).catch(() => resolve(null));
  });
}
function deleteDatabaseWithLock(dbName) {
  return new Promise(async resolve => {
    const lock = await acquireExclusiveLock(`netbridge-archive-db-${dbName}`);
    if (!lock) {
      resolve('active');
      return;
    }
    try {
      const req = indexedDB.deleteDatabase(dbName);
      req.onsuccess = () => { lock.release(); resolve('deleted'); };
      req.onerror = () => { lock.release(); resolve('error'); };
      req.onblocked = () => { lock.release(); resolve('blocked'); };
    } catch (_) {
      lock.release();
      resolve('error');
    }
  });
}
async function cleanupOrphanedArchiveDbs() {
  if (!window.indexedDB || !navigator.locks) return;
  const names = new Set([ARCHIVE_LEGACY_DB]);
  if (typeof indexedDB.databases === 'function') {
    try {
      const dbs = await indexedDB.databases();
      for (const db of dbs || []) {
        if (db && db.name && (db.name.startsWith(ARCHIVE_DB_PREFIX) || db.name === ARCHIVE_LEGACY_DB)) {
          names.add(db.name);
        }
      }
    } catch (_) {}
  }
  let anyBlocked = false;
  for (const name of names) {
    if (name === archiveDbName && archiveDb) continue;
    const outcome = await deleteDatabaseWithLock(name);
    if (outcome === 'blocked') anyBlocked = true;
  }
  archiveOrphanPending = anyBlocked;
  updateArchiveBanner();
}
function openArchiveDb(dbName) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName, ARCHIVE_SCHEMA_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(ARCHIVE_STORE)) {
        db.createObjectStore(ARCHIVE_STORE, { keyPath: 'key' });
      }
    };
    req.onsuccess = () => {
      const db = req.result;
      db.onversionchange = () => {
        try { db.close(); } catch (_) {}
        if (archiveDb === db) archiveDb = null;
      };
      resolve(db);
    };
    req.onblocked = () => reject(new Error('Archive database is blocked by another operation'));
    req.onerror = () => reject(req.error || new Error('IndexedDB open failed'));
  });
}
function nextArchiveIv() {
  const iv = new Uint8Array(12);
  iv.set(archiveIvSalt, 0);
  archiveIvCounter += 1;
  let c = archiveIvCounter;
  for (let i = 11; i >= 4; i -= 1) {
    iv[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  return iv;
}
function buildArchiveAad(sessionId, flowId) {
  return new TextEncoder().encode(JSON.stringify([
    ARCHIVE_SCHEMA_VERSION,
    archiveDeviceId || '',
    archiveCaFingerprint || '',
    sessionId || '',
    archiveId || '',
    flowId,
  ]));
}
function touchArchiveActivity(force = false) {
  if (!archiveKey && archiveCount === 0) return;
  const now = Date.now();
  if (!force && now - archiveLastActivityTouch < 5000) return;
  archiveLastActivityTouch = now;
  archiveExpiresAt = now + ARCHIVE_INACTIVITY_MS;
}
async function checkArchiveExpiry() {
  if (!archiveKey && archiveCount === 0) return false;
  if (archiveExpiresAt > 0 && Date.now() >= archiveExpiresAt) {
    await clearBrowserArchive(true);
    notice('Browser archive expired after 30 minutes of operator inactivity; RAM key destroyed.', true);
    return true;
  }
  return false;
}
async function archivePutBatch(details, sessionId) {
  if (!archiveDb || !archiveKey || !details.length) return { written: 0, quotaHit: false, limitHit: false, lastFlowId: null };
  if (await checkArchiveExpiry()) return { written: 0, quotaHit: false, limitHit: false, lastFlowId: null };

  const prepared = [];
  let projectedBytes = archiveBytes;
  let limitHit = false;
  for (const detail of details) {
    if (!detail || !detail.flow) continue;
    const plain = new TextEncoder().encode(JSON.stringify(detail));
    if (projectedBytes + plain.byteLength > archiveLimitBytes) {
      limitHit = true;
      break;
    }
    archiveSeq += 1;
    const seqKey = archiveSeq;
    const flowId = detail.flow.id;
    const iv = nextArchiveIv();
    const additionalData = buildArchiveAad(sessionId, flowId);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData, tagLength: 128 }, archiveKey, plain);
    prepared.push({
      summary: { ...detail.flow, _archiveKey: seqKey, _captureSessionId: sessionId },
      record: { key: seqKey, flowId, sessionId, iv: Array.from(iv), ct, approxBytes: plain.byteLength },
    });
    projectedBytes += plain.byteLength;
  }
  if (!prepared.length) {
    return { written: 0, quotaHit: false, limitHit, lastFlowId: null };
  }
  try {
    await new Promise((resolve, reject) => {
      const tx = archiveDb.transaction(ARCHIVE_STORE, 'readwrite');
      const store = tx.objectStore(ARCHIVE_STORE);
      for (const item of prepared) store.put(item.record);
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(tx.error || new Error('IndexedDB transaction aborted'));
      tx.onerror = () => reject(tx.error || new Error('IndexedDB write failed'));
    });
  } catch (err) {
    const isQuota = err && (err.name === 'QuotaExceededError' || /quota/i.test(err.message || ''));
    if (isQuota) return { written: 0, quotaHit: true, limitHit: false, lastFlowId: null };
    throw err;
  }
  for (const item of prepared) {
    archivedSummaries.set(item.record.key, item.summary);
    archiveCount += 1;
    archiveBytes += item.record.approxBytes;
  }
  return {
    written: prepared.length,
    quotaHit: false,
    limitHit,
    lastFlowId: prepared[prepared.length - 1].record.flowId,
  };
}
async function archiveGetDetail(archiveKeyId) {
  if (await checkArchiveExpiry()) return null;
  if (!archiveDb || !archiveKey || !archivedSummaries.has(archiveKeyId)) return null;
  const rec = await new Promise((resolve, reject) => {
    const tx = archiveDb.transaction(ARCHIVE_STORE, 'readonly');
    const req = tx.objectStore(ARCHIVE_STORE).get(archiveKeyId);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
  if (!rec) return null;
  const additionalData = buildArchiveAad(rec.sessionId, rec.flowId);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(rec.iv), additionalData, tagLength: 128 },
    archiveKey,
    rec.ct
  );
  return JSON.parse(new TextDecoder().decode(plain));
}
async function archiveGetAllDetails() {
  if (await checkArchiveExpiry()) return [];
  if (!archiveDb || !archiveKey || archiveCount === 0) return [];
  const recs = await new Promise((resolve, reject) => {
    const tx = archiveDb.transaction(ARCHIVE_STORE, 'readonly');
    const req = tx.objectStore(ARCHIVE_STORE).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
  recs.sort((a, b) => a.key - b.key);
  const dec = new TextDecoder();
  const out = [];
  for (const rec of recs) {
    const additionalData = buildArchiveAad(rec.sessionId, rec.flowId);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(rec.iv), additionalData, tagLength: 128 },
      archiveKey,
      rec.ct
    );
    out.push({ key: rec.key, detail: JSON.parse(dec.decode(plain)) });
  }
  return out;
}
function updateArchiveBanner() {
  const banner = $('archive-banner');
  const toggleBtn = $('toggle-browser-archive');
  if (toggleBtn) {
    toggleBtn.textContent = archiveEnabled
      ? `Browser Archive: On (${archiveCount})`
      : (archiveCount > 0 ? `Browser Archive: Paused (${archiveCount})` : 'Browser Archive: Off');
    toggleBtn.className = archiveEnabled ? 'primary' : 'quiet';
  }
  if (!banner) return;
  const show = archiveEnabled || archiveCount > 0 || archiveOrphanPending;
  banner.hidden = !show;
  if (!show) return;

  const pct = Math.min(100, Math.round((archiveBytes / Math.max(1, archiveLimitBytes)) * 100));
  const remainingMs = archiveExpiresAt ? Math.max(0, archiveExpiresAt - Date.now()) : ARCHIVE_INACTIVITY_MS;
  const expiringSoon = archiveCount > 0 && archiveExpiresAt > 0 && remainingMs <= ARCHIVE_WARN_REMAINING_MS;

  banner.classList.toggle('is-warn', pct >= 80 && pct < 95);
  banner.classList.toggle('is-crit', pct >= 95 || expiringSoon || archiveOrphanPending);

  const pill = $('archive-status-pill');
  if (pill) {
    if (archiveOrphanPending && !archiveEnabled && archiveCount === 0) {
      pill.textContent = 'CLEANUP PENDING';
      pill.className = 'archive-pill is-crit';
    } else if (archivePausedReason === 'limit' || archivePausedReason === 'quota') {
      pill.textContent = 'LIMIT REACHED';
      pill.className = 'archive-pill is-crit';
    } else if (expiringSoon) {
      pill.textContent = 'EXPIRING SOON';
      pill.className = 'archive-pill is-warn';
    } else if (archiveEnabled) {
      pill.textContent = 'RECORDING';
      pill.className = 'archive-pill is-on';
    } else {
      pill.textContent = 'PAUSED';
      pill.className = 'archive-pill';
    }
  }
  if ($('archive-count-val')) $('archive-count-val').textContent = archiveCount.toLocaleString();
  if ($('archive-missed-val')) {
    $('archive-missed-val').textContent = archiveMissedCount.toLocaleString();
    $('archive-missed-val').className = archiveMissedCount > 0 ? 'state-warn' : '';
  }
  if ($('archive-bytes-val')) $('archive-bytes-val').textContent = formatBytes(archiveBytes);
  const bar = $('archive-progress-bar');
  if (bar) {
    bar.style.width = `${pct}%`;
    bar.className = pct >= 95 ? 'archive-progress__bar is-crit' : (pct >= 80 ? 'archive-progress__bar is-warn' : 'archive-progress__bar');
  }
  const desc = $('archive-banner-desc');
  if (desc) {
    if (archiveOrphanPending && !archiveEnabled && archiveCount === 0) {
      desc.textContent = 'Orphaned encrypted archive data from an earlier session is awaiting browser cleanup (key already destroyed).';
    } else if (archivePausedReason === 'limit' || archivePausedReason === 'quota') {
      desc.textContent = 'Storage limit or browser quota reached. Recording is paused; existing archived flows are preserved. Export or clear to continue.';
    } else if (pct >= 80) {
      desc.textContent = `Archive storage is at ${pct}% of the configured limit. Export required records soon.`;
    } else {
      desc.textContent = 'This browser holds encrypted, potentially sensitive and unredacted network traffic. Export required records before leaving this session.';
    }
  }
  const note = $('archive-expiry-note');
  if (note) {
    if (expiringSoon) {
      const mins = Math.max(1, Math.ceil(remainingMs / 60000));
      note.textContent = `Inactivity warning: archive key will be destroyed in ~${mins} minute${mins === 1 ? '' : 's'} unless you interact with the page.`;
    } else {
      note.textContent = 'Archive expires after 30 minutes of operator inactivity. Reloading or closing this session destroys access to archived records.';
    }
  }
  const pauseBtn = $('archive-pause-btn');
  if (pauseBtn) {
    pauseBtn.textContent = archiveEnabled ? 'Pause archive' : 'Resume archive';
    pauseBtn.disabled = !archiveKey && archiveCount === 0;
  }
  const exportBtn = $('archive-export-btn');
  if (exportBtn) exportBtn.disabled = archiveCount === 0;
}
async function clearBrowserArchive(silent = false) {
  archiveEnabled = false;
  archivePausedReason = '';
  archiveKey = null;
  archiveIvSalt = null;
  archiveIvCounter = 0;
  archiveSessionId = '';
  archiveHighWaterId = 0;
  archiveSeq = 0;
  archiveCount = 0;
  archiveMissedCount = 0;
  archiveBytes = 0;
  archiveExpiresAt = 0;
  archiveNeedsRevalidation = false;
  archivedSummaries.clear();
  const dbNameToDelete = archiveDbName;
  archiveDbName = '';
  archiveId = '';
  if (archiveDb) {
    try { archiveDb.close(); } catch (_) {}
    archiveDb = null;
  }
  if (archiveDbLock) { archiveDbLock.release(); archiveDbLock = null; }
  if (archiveWriterLock) { archiveWriterLock.release(); archiveWriterLock = null; }
  let deleteOutcome = 'deleted';
  if (dbNameToDelete && window.indexedDB) {
    deleteOutcome = await deleteDatabaseWithLock(dbNameToDelete);
  }
  archiveOrphanPending = (deleteOutcome === 'blocked');
  updateArchiveBanner();
  if ($('inspector') && !$('inspector').hidden) renderFlows();
  if (!silent) {
    notice(
      deleteOutcome === 'blocked'
        ? 'RAM encryption key destroyed, but IndexedDB deletion was blocked; orphaned ciphertext awaits cleanup.'
        : 'Cleared encrypted browser archive and destroyed RAM encryption key.'
    );
  }
}
async function startOrResumeBrowserArchive() {
  if (await checkArchiveExpiry()) return;
  if (archiveEnabled) {
    archiveEnabled = false;
    archivePausedReason = 'manual';
    updateArchiveBanner();
    notice(`Browser Archive paused (${archiveCount} flow${archiveCount === 1 ? '' : 's'} retained in this tab).`);
    return;
  }
  if (!window.crypto || !window.crypto.subtle || !window.indexedDB || !navigator.locks) {
    notice('Encrypted Browser Archive requires WebCrypto, IndexedDB, and Web Locks over HTTPS. Plaintext fallback is disabled.', true);
    return;
  }
  if (archivePausedReason === 'limit' && archiveBytes >= archiveLimitBytes) {
    notice('Archive storage limit reached. Increase the limit or export/clear the archive before resuming.', true);
    return;
  }
  try {
    if (!archiveWriterLock) {
      archiveWriterLock = await acquireExclusiveLock(ARCHIVE_WRITER_LOCK);
      if (!archiveWriterLock) {
        notice('Another open tab already owns the active Browser Archive writer.', true);
        return;
      }
    }
    if (!archiveId) {
      archiveId = newRandomHex(16);
      archiveDbName = `${ARCHIVE_DB_PREFIX}${archiveId}`;
      archiveDbLock = await acquireExclusiveLock(`netbridge-archive-db-${archiveDbName}`);
      if (!archiveDbLock) {
        archiveId = '';
        archiveDbName = '';
        archiveWriterLock.release();
        archiveWriterLock = null;
        notice('Unable to acquire exclusive archive database lock.', true);
        return;
      }
    }
    if (!archiveKey) {
      archiveKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
      archiveIvSalt = crypto.getRandomValues(new Uint8Array(4));
      archiveIvCounter = 0;
    }
    if (!archiveDb) {
      archiveDb = await openArchiveDb(archiveDbName);
    }
    clearInspectorCache();
    archiveEnabled = true;
    archivePausedReason = '';
    touchArchiveActivity(true);
    updateArchiveBanner();
    await syncBrowserArchive();
    notice('Encrypted Browser Archive active (RAM-only AES-256-GCM key).');
  } catch (error) {
    archiveEnabled = false;
    updateArchiveBanner();
    notice(error.message || 'Unable to initialize Encrypted Browser Archive', true);
  }
}
async function syncBrowserArchive() {
  if (!archiveEnabled || archiveSyncBusy || !archiveKey || !archiveDb) return;
  if (await checkArchiveExpiry()) return;
  archiveSyncBusy = true;
  try {
    for (let batch = 0; batch < 6; batch += 1) {
      const res = await api(`flows-since?after_id=${encodeURIComponent(archiveHighWaterId)}&limit=25`);
      if (res.device_id) {
        if (archiveDeviceId && archiveDeviceId !== res.device_id) {
          await clearBrowserArchive(true);
          notice('Device identity changed; destroyed previous browser archive.', true);
          return;
        }
        archiveDeviceId = res.device_id;
      }
      const srvSession = res.capture_session_id || '';
      if (srvSession && archiveSessionId && archiveSessionId !== srvSession) {
        // Controller restarted or device ring was cleared -> reset cursor without wiping archive
        archiveSessionId = srvSession;
        archiveHighWaterId = 0;
        break;
      }
      if (srvSession && !archiveSessionId) archiveSessionId = srvSession;

      const minAvail = res.min_available_id || 0;
      if (minAvail > 0 && archiveHighWaterId > 0 && minAvail > archiveHighWaterId + 1) {
        archiveMissedCount += (minAvail - (archiveHighWaterId + 1));
      }
      const items = res.items || [];
      if (!items.length) break;

      let prevId = Math.max(archiveHighWaterId, minAvail > 0 ? minAvail - 1 : 0);
      for (const detail of items) {
        const fid = detail && detail.flow ? detail.flow.id : 0;
        if (prevId > 0 && fid > prevId + 1) {
          archiveMissedCount += (fid - (prevId + 1));
        }
        if (fid > prevId) prevId = fid;
      }

      const writeRes = await archivePutBatch(items, archiveSessionId);
      if (writeRes.lastFlowId !== null && writeRes.lastFlowId > archiveHighWaterId) {
        archiveHighWaterId = writeRes.lastFlowId;
      }
      if (writeRes.limitHit || writeRes.quotaHit) {
        archiveEnabled = false;
        archivePausedReason = writeRes.quotaHit ? 'quota' : 'limit';
        notice('Browser archive storage limit reached; recording paused while preserving existing records.', true);
        break;
      }
      if (!res.has_more) break;
    }
    updateArchiveBanner();
  } catch (_) {
    // Non-fatal: temporary network failure pauses delivery without destroying archive
  } finally {
    archiveSyncBusy = false;
  }
}
function mergedFlows() {
  if (archiveCount === 0) return lastFlows;
  const out = Array.from(archivedSummaries.values());
  const seenKey = new Set();
  for (const f of lastFlows) {
    const alreadyArchived = Array.from(archivedSummaries.values()).some(
      a => a.id === f.id && a._captureSessionId === archiveSessionId
    );
    if (!alreadyArchived) out.push(f);
  }
  return out.sort((a, b) => (b._archiveKey || (1000000000 + b.id)) - (a._archiveKey || (1000000000 + a.id)));
}

function saveInspectorCache() {
  if (archiveEnabled || archiveCount > 0) return;
  try {
    const payload = () => JSON.stringify({
      flows: lastFlows,
      details: Array.from(flowDetailCache.entries()),
    });
    try {
      sessionStorage.setItem(INSPECTOR_CACHE_KEY, payload());
    } catch (_) {
      while (flowDetailCache.size > 0) {
        const oldestKey = flowDetailCache.keys().next().value;
        flowDetailCache.delete(oldestKey);
        try {
          sessionStorage.setItem(INSPECTOR_CACHE_KEY, payload());
          return;
        } catch (_) {}
      }
      sessionStorage.setItem(INSPECTOR_CACHE_KEY, JSON.stringify({ flows: lastFlows, details: [] }));
    }
  } catch (_) {}
}
function loadInspectorCache() {
  try {
    const raw = sessionStorage.getItem(INSPECTOR_CACHE_KEY);
    if (!raw) return false;
    const data = JSON.parse(raw);
    if (!data || !Array.isArray(data.flows) || !data.flows.length) return false;
    lastFlows = data.flows;
    flowDetailCache = new Map(Array.isArray(data.details) ? data.details : []);
    return true;
  } catch (_) {
    return false;
  }
}
function clearInspectorCache() {
  flowDetailCache.clear();
  try { sessionStorage.removeItem(INSPECTOR_CACHE_KEY); } catch (_) {}
}
function showOfflineCachedInspector(message) {
  showView('inspector');
  $('hb-flows').textContent = `${lastFlows.length} / 100`;
  $('hb-last-event').textContent = lastFlows.length ? formatClock(lastFlows[0].time, true) : 'None yet';
  if ($('hb-state')) {
    $('hb-state').textContent = 'OFFLINE (CACHED)';
    $('hb-state').className = 'state-warn';
  }
  updateClientFilterOptions();
  renderFlows();
  notice(message, true);
}
const secure = location.protocol === 'https:';
const httpsBase = `https://${location.hostname}`;
function currentPath() { return location.pathname; }
function isInspectorPage() { return currentPath() === '/inspector'; }
function isAdminPage() { return currentPath() === '/admin'; }
function isSetupPage() { return !isInspectorPage() && !isAdminPage(); }

function notice(text, error = false) {
  $('notice').hidden = false;
  $('notice').className = error ? 'error' : '';
  $('notice').textContent = text;
}
async function api(action, data) {
  const response = await fetch(`/api/${action}`, {
    method: data === undefined ? 'GET' : 'POST',
    credentials: 'same-origin',
    headers: data === undefined ? {} : { 'Content-Type': 'application/json', 'X-NetBridge-CSRF': csrf },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(result.error || 'Request failed');
    error.status = response.status;
    throw error;
  }
  if (result.csrf) csrf = result.csrf;
  return result;
}
function showView(id) {
  for (const name of ['setup', 'authentication', 'admin', 'inspector']) {
    $(name).hidden = name !== id;
  }
  $('page-shell').classList.toggle('site-shell--inspector', id === 'inspector');
}
function busy(form, action) {
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const button = form.querySelector('button');
    button.disabled = true;
    try { await action(); } catch (error) { notice(error.message, true); } finally { button.disabled = false; }
  });
}
function setInspectionState(state, proxyHealth) {
  inspectionState = state || 'off';
  const meta = $('meta-inspection');
  const metric = $('inspection-state');
  const heading = $('control-heading');
  const hb = $('hb-state');
  const detail = proxyHealth && proxyHealth.detail && proxyHealth.detail !== 'ok' && proxyHealth.detail !== 'off'
    ? ` (${proxyHealth.detail.replace(/_/g, ' ')})`
    : '';
  const label = inspectionState === 'on' ? 'active' : inspectionState === 'degraded' ? 'fail-open' : 'off';
  if (meta) {
    meta.textContent = label;
    meta.className = inspectionState === 'on' ? 'state-on' : inspectionState === 'degraded' ? 'state-warn' : 'state-off';
  }
  if (metric) metric.textContent = inspectionState === 'on' ? 'Active' : inspectionState === 'degraded' ? 'Fail-open' : 'Off';
  if (heading) heading.textContent = inspectionState === 'on' ? 'Inspection is active' : inspectionState === 'degraded' ? `Fail-open active${detail || ' (proxy unavailable)'}` : 'Inspection is currently off';
  if (hb) {
    hb.textContent = flowsPaused ? `${label.toUpperCase()} (PAUSED)` : label.toUpperCase();
    hb.className = inspectionState === 'on' ? 'state-on' : inspectionState === 'degraded' ? 'state-warn' : '';
    hb.title = detail ? `Proxy health: ${proxyHealth.detail}` : '';
  }
  for (const btnId of ['admin-toggle-inspection', 'inspector-toggle-inspection']) {
    const btn = $(btnId);
    if (!btn) continue;
    btn.textContent = inspectionState === 'off' ? 'Enable inspection' : 'Disable inspection';
    btn.className = inspectionState === 'off' ? 'primary' : 'danger-button';
  }
}
function formatBytes(n) {
  if (!n) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1048576).toFixed(2)} MiB`;
}
function formatClock(iso, withMs = false) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const s = String(d.getSeconds()).padStart(2, '0');
  if (!withMs) return `${h}:${m}:${s}`;
  const ms = String(d.getMilliseconds()).padStart(3, '0');
  return `${h}:${m}:${s}.${ms}`;
}
function flowTypeInfo(f) {
  if (f.state === 'tls_failed') return ['TLS', 'err'];
  if (f.state === 'error') return ['ERR', 'err'];
  if (f.state === 'tcp') return [f.scheme === 'tls-tcp' ? 'TLS-TCP' : 'TCP', 'tcp'];
  if (f.state === 'websocket') return ['WS', 'ws'];
  if (f.status >= 300 && f.status < 400) return ['30x', 'redir'];
  const c = (f.content_type || '').toLowerCase();
  if (c.startsWith('image/')) return ['IMG', 'img'];
  if (c.includes('json')) return ['JSON', 'json'];
  if (c.includes('javascript')) return ['JS', 'js'];
  if (c.includes('html')) return ['HTML', 'html'];
  if (c.includes('css')) return ['CSS', 'css'];
  if (c.startsWith('text/')) return ['TXT', 'ok'];
  if (c.includes('octet-stream') || c.includes('zip') || c.includes('pdf') || c.includes('protobuf')) return ['BIN', 'bin'];
  return [f.state === 'decrypted' ? 'HTTPS' : 'HTTP', 'ok'];
}
function flowTargetLabel(f) {
  if (f.state === 'tcp') {
    const port = f.server_port ? `:${f.server_port}` : '';
    const dst = f.server_ip && f.host !== f.server_ip ? `${f.host} (${f.server_ip}${port})` : `${f.host}${port}`;
    return `${f.scheme}://${dst}`;
  }
  const scheme = f.scheme || (f.state === 'decrypted' ? 'https' : 'http');
  return `${scheme}://${f.host || f.server_ip}${f.path || '/'}`;
}
function updateClientFilterOptions() {
  const select = $('filter-client');
  if (!select) return;
  const current = select.value;
  const seen = new Map();
  for (const c of lastClients) { if (c.ip) seen.set(c.ip, `${c.name} (${c.ip})`); }
  for (const f of mergedFlows()) { if (f.client_ip && !seen.has(f.client_ip)) seen.set(f.client_ip, f.client_ip); }
  const first = document.createElement('option'); first.value = ''; first.textContent = 'All clients';
  const options = [first];
  for (const [ip, label] of seen.entries()) {
    const opt = document.createElement('option'); opt.value = ip; opt.textContent = label; options.push(opt);
  }
  select.replaceChildren(...options);
  select.value = seen.has(current) ? current : '';
}
function matchesFilter(f) {
  if (deepSearchMatchMap && !deepSearchMatchMap.has(f._archiveKey || f.id)) return false;
  const clientFilter = $('filter-client').value;
  const q = $('filter-host').value.trim().toLowerCase();
  const stateFilter = $('filter-state').value;
  if (clientFilter && f.client_ip !== clientFilter) return false;
  if (q) {
    const hay = `${f.host} ${f.path} ${f.server_ip} ${f.server_port} ${f.method} ${f.status} ${f.content_type} ${f.detail}`.toLowerCase();
    if (!hay.includes(q)) return false;
  }
  if (stateFilter === 'http' && f.state !== 'decrypted' && f.state !== 'passthrough') return false;
  if (stateFilter === 'tcp' && f.state !== 'tcp') return false;
  if (stateFilter === 'websocket' && f.state !== 'websocket') return false;
  if (stateFilter === 'images' && !(f.content_type || '').toLowerCase().startsWith('image/')) return false;
  if (stateFilter === 'json' && !(f.content_type || '').toLowerCase().includes('json')) return false;
  if (stateFilter === 'errors' && f.state !== 'tls_failed' && f.state !== 'error') return false;
  if (stateFilter === 'http45' && !(f.status >= 400)) return false;
  return true;
}
function renderFlows() {
  const container = $('flows');
  const allFlows = mergedFlows();
  const filtered = allFlows.filter(matchesFilter);
  container.replaceChildren();
  if (!filtered.length) {
    const p = document.createElement('p'); p.className = 'empty';
    p.textContent = allFlows.length ? 'No captured flows match the active filters.' : (inspectionState === 'on' ? 'Inspection active. Waiting for HTTP, HTTPS, WebSocket, or application TCP traffic…' : 'No traffic recorded. Enable inspection and approve a trusted device to capture flows.');
    container.append(p); return;
  }
  for (const f of filtered) {
    const rowKey = f._archiveKey || f.id;
    const [badgeText, kind] = flowTypeInfo(f);
    const row = document.createElement('button');
    row.type = 'button';
    row.className = `flow-row kind-${kind}${selectedFlowId === rowKey ? ' selected' : ''}`;
    const cTime = document.createElement('span'); cTime.className = 'flow-time';
    cTime.textContent = formatClock(f.time, false); cTime.title = f.time || '';
    const cType = document.createElement('span'); cType.className = `flow-type kind-${kind}`; cType.textContent = badgeText;
    const cPath = document.createElement('span'); cPath.className = 'flow-path'; cPath.textContent = flowTargetLabel(f); cPath.title = cPath.textContent;
    const cMethod = document.createElement('span'); cMethod.className = 'flow-cell'; cMethod.textContent = f.method;
    const isWsNormal = f.state === 'websocket' && (f.status === 101 || f.status === 1000 || f.status === 1001);
    const isErrStatus = (f.status >= 400 && !isWsNormal) || f.state === 'tls_failed' || f.state === 'error';
    const cStatus = document.createElement('span'); cStatus.className = isErrStatus ? 'flow-cell warn' : 'flow-cell';
    cStatus.textContent = f.status ? String(f.status) : (f.state === 'tcp' ? 'TCP' : (f.state === 'tls_failed' ? 'TLS' : 'ERR'));
    const cSize = document.createElement('span'); cSize.className = 'flow-cell num';
    cSize.textContent = f.state === 'tcp' ? formatBytes((f.req_bytes || 0) + (f.bytes || 0)) : formatBytes(f.bytes);
    const cLat = document.createElement('span'); cLat.className = 'flow-cell num'; cLat.textContent = `${f.duration_ms || 0}ms`;
    row.append(cTime, cType, cPath, cMethod, cStatus, cSize, cLat);
    row.addEventListener('click', () => selectFlow(f.id, f._archiveKey || null));
    container.append(row);
  }
}
async function selectFlow(flowId, archiveKeyId = null) {
  selectedFlowId = archiveKeyId || flowId;
  renderFlows();
  $('inspector-empty').hidden = true;
  $('inspector-content').hidden = false;
  $('inspector-title').textContent = 'Loading flow…';
  $('inspector-subtitle').textContent = '';
  $('inspector-body').replaceChildren();
  try {
    if (archiveKeyId) {
      const archived = await archiveGetDetail(archiveKeyId);
      if (archived) {
        selectedDetail = archived;
        renderInspector();
        return;
      }
    }
    selectedDetail = await api(`flow?id=${encodeURIComponent(flowId)}`);
    flowDetailCache.set(flowId, selectedDetail);
    saveInspectorCache();
    renderInspector();
  } catch (error) {
    if (flowDetailCache.has(flowId)) {
      selectedDetail = flowDetailCache.get(flowId);
      renderInspector();
      notice(`Offline — showing browser-cached details for flow #${flowId}.`, true);
      return;
    }
    const summary = mergedFlows().find(f => (archiveKeyId ? f._archiveKey === archiveKeyId : f.id === flowId));
    if (summary) {
      selectedDetail = {
        flow: summary,
        request: { captured: 0, size: summary.req_bytes || 0 },
        response: { captured: 0, size: summary.bytes || 0 },
      };
      renderInspector();
      notice('Offline — showing cached flow summary (full payload was not cached before disconnect).', true);
      return;
    }
    $('inspector-title').textContent = 'Unable to load flow';
    $('inspector-subtitle').textContent = error.message;
  }
}
function makeKVTable(rows) {
  const table = document.createElement('table'); table.className = 'kv-table';
  const tbody = document.createElement('tbody');
  for (const [k, v] of rows) {
    const tr = document.createElement('tr');
    const th = document.createElement('th'); th.textContent = k;
    const td = document.createElement('td'); td.textContent = v;
    tr.append(th, td); tbody.append(tr);
  }
  table.append(tbody);
  return table;
}
function prettyText(text, contentType) {
  const c = (contentType || '').toLowerCase();
  if (c.includes('json') || text.trimStart().startsWith('{') || text.trimStart().startsWith('[')) {
    try { return JSON.stringify(JSON.parse(text), null, 2); } catch (_) {}
  }
  if (c.includes('x-www-form-urlencoded')) {
    try {
      const params = new URLSearchParams(text);
      const lines = [];
      for (const [k, v] of params.entries()) lines.push(`${k} = ${v}`);
      if (lines.length) return lines.join('\n');
    } catch (_) {}
  }
  return text;
}
function renderMessageTab(part) {
  const f = selectedDetail.flow;
  const view = part === 'request' ? selectedDetail.request : selectedDetail.response;
  const wrap = document.createElement('div');
  const banner = document.createElement('div');
  banner.className = part === 'response' && f.status >= 400 ? 'msg-banner warn' : 'msg-banner';
  if (part === 'request') {
    banner.textContent = f.state === 'tcp'
      ? `${f.method} Client -> Server (${f.server_ip || f.host}:${f.server_port || '?'}) · ${formatBytes(view.size)}`
      : `${f.method} ${f.path || '/'} ${f.http_version || 'HTTP/1.1'}`;
  } else {
    banner.textContent = f.state === 'tcp'
      ? `${f.method} Server -> Client · ${formatBytes(view.size)}`
      : f.status ? `${f.resp_http_version || 'HTTP/1.1'} ${f.status} ${f.reason || ''}` : `${f.reason || f.state} · ${f.detail || ''}`;
  }
  wrap.append(banner);

  const headers = part === 'request' ? (f.request_headers || []) : (f.response_headers || []);
  if (headers.length) {
    const det = document.createElement('details'); det.className = 'headers-box'; det.open = true;
    const sum = document.createElement('summary'); sum.textContent = `Headers (${headers.length})`;
    det.append(sum, makeKVTable(headers));
    wrap.append(det);
  }

  const bar = document.createElement('div'); bar.className = 'payload-toolbar';
  const modes = document.createElement('div'); modes.className = 'mode-group';
  const currentMode = viewMode[part];
  for (const [key, label] of [['auto', part === 'response' ? 'Preview' : 'Pretty'], ['raw', 'Raw'], ['hex', 'Hex Dump']]) {
    const btn = document.createElement('button'); btn.type = 'button';
    btn.className = currentMode === key ? 'mode-btn active' : 'mode-btn';
    btn.textContent = label;
    btn.disabled = !view.captured;
    btn.addEventListener('click', () => { viewMode[part] = key; renderInspector(); });
    modes.append(btn);
  }
  const actions = document.createElement('div'); actions.className = 'mode-group';
  if (view.captured) {
    const useLocalArchive = Boolean(f._archiveKey || (archiveCount > 0 && (view.hex || view.text || view.image_data_url)));
    const dlRaw = document.createElement('a'); dlRaw.className = 'mode-btn link';
    dlRaw.href = `/api/flow-raw?id=${encodeURIComponent(f.id)}&part=${part}&format=raw&download=1`;
    dlRaw.textContent = 'Download Raw';
    dlRaw.addEventListener('click', event => {
      event.preventDefault();
      requestExportConfirmation(
        dlRaw.href,
        'Raw Payload',
        useLocalArchive ? { url: dlRaw.href, format: 'flow-raw', flowId: f.id, part, view } : null
      );
    });
    const dlHex = document.createElement('a'); dlHex.className = 'mode-btn link';
    dlHex.href = `/api/flow-raw?id=${encodeURIComponent(f.id)}&part=${part}&format=hex&download=1`;
    dlHex.textContent = 'Export Hex';
    dlHex.addEventListener('click', event => {
      event.preventDefault();
      requestExportConfirmation(
        dlHex.href,
        'Hex Dump',
        useLocalArchive ? { url: dlHex.href, format: 'flow-hex', flowId: f.id, part, view } : null
      );
    });
    actions.append(dlRaw, dlHex);
  }
  bar.append(modes, actions);
  wrap.append(bar);

  if (!view.captured) {
    const empty = document.createElement('p'); empty.className = 'empty small';
    if (f.payload_status === 'streamed' && view.size > 0) {
      empty.textContent = `Streamed payload (${formatBytes(view.size)}) — exceeded the 512 KiB buffer limit and was passed through without buffering in RAM.`;
    } else {
      empty.textContent = f.detail && part === 'response' ? `No payload captured (${f.detail}).` : 'Empty payload (0 bytes).';
    }
    wrap.append(empty);
    return wrap;
  }
  if (view.truncated || view.hex_truncated || view.text_truncated) {
    const note = document.createElement('p'); note.className = 'small trunc-note';
    if (view.decoded_size_known === false) {
      const minText = view.decoded_bytes_min ? `>= ${formatBytes(view.decoded_bytes_min)} decoded` : 'Unknown decoded size';
      const wireText = view.wire_bytes ? `, ${formatBytes(view.wire_bytes)} compressed/wire` : '';
      const encText = view.content_encoding ? ` (${view.content_encoding})` : '';
      note.textContent = `Showing ${formatBytes(Math.min(view.captured, 32768))} preview (${formatBytes(view.captured)} retained · ${minText}${wireText}${encText}).`;
    } else {
      note.textContent = `Showing ${formatBytes(Math.min(view.captured, 32768))} preview of ${formatBytes(view.size)} total (${formatBytes(view.captured)} captured). Use Download Raw or Export Hex for full payload.`;
    }
    wrap.append(note);
  }

  const resolvedMode = currentMode === 'auto'
    ? (view.is_inline_image ? 'image' : (view.is_text ? 'pretty' : 'hex'))
    : currentMode;

  if (resolvedMode === 'image') {
    const box = document.createElement('div'); box.className = 'image-preview-box';
    const img = document.createElement('img');
    img.src = view.image_data_url || `/api/flow-raw?id=${encodeURIComponent(f.id)}&part=${part}&format=raw`;
    img.alt = `${f.host}${f.path}`;
    const cap = document.createElement('p'); cap.className = 'small';
    cap.textContent = `${view.content_type} · ${formatBytes(view.size)}`;
    box.append(img, cap);
    wrap.append(box);
  } else if (resolvedMode === 'hex') {
    const pre = document.createElement('pre'); pre.className = 'payload-pre hex';
    pre.textContent = view.hex;
    wrap.append(pre);
  } else if (!view.is_text) {
    const warn = document.createElement('p'); warn.className = 'small trunc-note';
    warn.textContent = `Binary payload (${view.content_type || 'application/octet-stream'}); showing hex dump.`;
    const pre = document.createElement('pre'); pre.className = 'payload-pre hex';
    pre.textContent = view.hex;
    wrap.append(warn, pre);
  } else {
    const pre = document.createElement('pre'); pre.className = 'payload-pre';
    pre.textContent = resolvedMode === 'pretty' ? prettyText(view.text, view.content_type) : view.text;
    wrap.append(pre);
  }
  return wrap;
}
function renderDetailsTab() {
  const f = selectedDetail.flow;
  const wrap = document.createElement('div'); wrap.className = 'details-stack';
  const cc = f.client_conn || {};
  const sc = f.server_conn || {};
  const t = f.timings || {};

  const addSection = (title, rows) => {
    if (!rows.length) return;
    const h = document.createElement('h4'); h.className = 'detail-heading'; h.textContent = title;
    wrap.append(h, makeKVTable(rows));
  };

  addSection('Client Connection', [
    ['Client Address', `${cc.ip || f.client_ip || '—'}${cc.port ? ':' + cc.port : ''}`],
    ['TLS', cc.tls ? 'Yes' : 'No'],
    ['TLS Version', cc.tls_version || '—'],
    ['Cipher', cc.cipher || '—'],
    ['SNI', cc.sni || '—'],
    ['ALPN', cc.alpn || '—'],
    ...(cc.error ? [['Client Error', cc.error]] : []),
  ]);

  addSection('Server Connection', [
    ['Server Address', `${sc.ip || f.server_ip || '—'}:${sc.port || f.server_port || '—'}`],
    ['TLS', sc.tls ? 'Yes' : 'No'],
    ['TLS Version', sc.tls_version || '—'],
    ['Cipher', sc.cipher || '—'],
    ['ALPN', sc.alpn || '—'],
    ...(sc.error ? [['Server Error', sc.error]] : []),
  ]);

  if (sc.cert) {
    addSection('Upstream Server Certificate', [
      ['Subject', sc.cert.subject || '—'],
      ['Issuer', sc.cert.issuer || '—'],
      ['SHA-256', sc.cert.fingerprint || '—'],
      ['Valid From', sc.cert.not_before || '—'],
      ['Valid Until', sc.cert.not_after || '—'],
    ]);
  }

  const reqSizeText = f.req_decoded_size_known === false
    ? `Unknown decoded size (${f.req_decoded_bytes_min ? `>= ${formatBytes(f.req_decoded_bytes_min)}, ` : ''}${formatBytes(f.req_wire_bytes || 0)} wire, ${formatBytes(f.req_retained_bytes || 0)} retained)`
    : `${formatBytes(f.req_bytes || 0)}${f.req_retained_bytes !== undefined && f.req_retained_bytes < (f.req_bytes || 0) ? ` (${formatBytes(f.req_retained_bytes)} retained)` : ''}`;
  const respSizeText = f.resp_decoded_size_known === false
    ? `Unknown decoded size (${f.resp_decoded_bytes_min ? `>= ${formatBytes(f.resp_decoded_bytes_min)}, ` : ''}${formatBytes(f.resp_wire_bytes || 0)} wire, ${formatBytes(f.resp_retained_bytes || 0)} retained)`
    : `${formatBytes(f.bytes || 0)}${f.resp_retained_bytes !== undefined && f.resp_retained_bytes < (f.bytes || 0) ? ` (${formatBytes(f.resp_retained_bytes)} retained)` : ''}`;
  const timingRows = [
    ['Started (UTC)', t.start || f.time || '—'],
    ['TLS Handshake', t.tls_setup || '—'],
    ['Completed', t.end || '—'],
    ['Duration', `${f.duration_ms || 0} ms`],
    ['Request Size', reqSizeText],
    ['Response Size', respSizeText],
    ['Payload Status', f.payload_status || '—'],
  ];
  if (f.total_messages !== undefined) {
    const msgText = f.omitted_messages > 0
      ? `${f.retained_messages} / ${f.total_messages} (${f.omitted_messages} omitted)`
      : `${f.total_messages}`;
    timingRows.push(['Messages', msgText]);
  }
  if (f.detail) timingRows.push(['Note', f.detail]);
  addSection('Timing & Sizes', timingRows);

  if (Array.isArray(f.frames) && f.frames.length) {
    const totalLabel = f.total_messages && f.total_messages > f.frames.length ? `${f.frames.length} of ${f.total_messages}` : `${f.frames.length}`;
    const h = document.createElement('h4'); h.className = 'detail-heading'; h.textContent = `Stream Frames / Chunks (${totalLabel})`;
    const rows = f.frames.map((fr, idx) => [`#${idx + 1} ${fr.dir}`, `${formatBytes(fr.len)} ${fr.type || ''} @ ${fr.time || ''}`.trim()]);
    wrap.append(h, makeKVTable(rows));
  }
  return wrap;
}
function renderInspector() {
  if (!selectedDetail || !selectedDetail.flow) return;
  const f = selectedDetail.flow;
  $('inspector-title').textContent = flowTargetLabel(f);
  $('inspector-subtitle').textContent = `${f.time || ''} · ${f.client_ip || ''} -> ${f.server_ip || f.host}:${f.server_port || ''}`;
  for (const tabBtn of document.querySelectorAll('.inspector-tabs .tab')) {
    tabBtn.classList.toggle('active', tabBtn.dataset.tab === activeTab);
  }
  const body = $('inspector-body'); body.replaceChildren();
  if (activeTab === 'request') body.append(renderMessageTab('request'));
  else if (activeTab === 'response') body.append(renderMessageTab('response'));
  else body.append(renderDetailsTab());
}
function scheduleRefresh() {
  clearTimeout(refreshTimer);
  if ($('admin').hidden && $('inspector').hidden) return;
  const pollDelayMs = (archiveEnabled && inspectionState === 'on') ? 1500 : 3000;
  refreshTimer = setTimeout(() => refreshProtected().catch(async error => {
    if (error.status === 401) {
      await clearBrowserArchive(true);
      if (authChannel) authChannel.postMessage({ type: 'invalidate', reason: '401' });
      showView('authentication');
      notice('Session expired. Sign in again.');
    } else if (isInspectorPage() && mergedFlows().length) {
      archiveNeedsRevalidation = true;
      if ($('hb-state')) {
        $('hb-state').textContent = 'OFFLINE (CACHED)';
        $('hb-state').className = 'state-warn';
      }
      notice(`Connection lost — viewing ${mergedFlows().length} locally retained flows. Delivery paused until reconnect.`, true);
      scheduleRefresh();
    } else {
      archiveNeedsRevalidation = true;
      notice(error.message, true);
      scheduleRefresh();
    }
  }), pollDelayMs);
}
async function refreshProtected() {
  if (pollBusy) return;
  pollBusy = true;
  try {
    const state = await api('status');
    archiveNeedsRevalidation = false;
    if (state.device_id) {
      if (archiveDeviceId && archiveDeviceId !== state.device_id && archiveCount > 0) {
        await clearBrowserArchive(true);
        notice('Device identity changed; destroyed previous browser archive.', true);
      }
      archiveDeviceId = state.device_id;
    }
    if (state.ca && state.ca.fingerprint) {
      if (archiveCaFingerprint && archiveCaFingerprint !== state.ca.fingerprint && archiveCount > 0) {
        await clearBrowserArchive(true);
        notice('CA fingerprint changed; destroyed previous browser archive.', true);
      }
      archiveCaFingerprint = state.ca.fingerprint;
    }
    if (state.capture_stats) archiveLastCaptureStats = state.capture_stats;
    setInspectionState(state.inspection, state.proxy_health);
    const wanText = state.wan_connected ? 'connected' : 'offline';
    $('meta-wan').textContent = wanText;
    lastClients = state.clients || [];
    if (!flowsPaused) lastFlows = state.flows || [];
    if (archiveEnabled && !flowsPaused) {
      await syncBrowserArchive();
    }
    updateArchiveBanner();

    if (isInspectorPage()) {
      showView('inspector');
      if (!filterSaveBusy && Array.isArray(state.capture_filters)) {
        const active = new Set(state.capture_filters);
        for (const cb of document.querySelectorAll('#ingest-bar input[data-ingest]')) {
          cb.checked = active.has(cb.dataset.ingest);
        }
        if ($('ingest-skip-noise')) $('ingest-skip-noise').checked = Boolean(state.capture_skip_noise);
        if ($('ingest-host') && document.activeElement !== $('ingest-host')) {
          $('ingest-host').value = state.capture_host_filter || '';
        }
      }
      $('hb-flows').textContent = archiveCount > 0
        ? `${lastFlows.length} / 100 (${archiveCount} archived)`
        : `${lastFlows.length} / 100`;
      if ($('hb-inspected')) {
        const ic = state.inspected_clients || 0;
        $('hb-inspected').textContent = `${ic} client${ic === 1 ? '' : 's'}`;
        const warn = state.inspection === 'on' && ic === 0;
        $('hb-inspected').className = warn ? 'state-warn' : (ic > 0 ? 'state-on' : '');
        $('hb-inspected').title = warn
          ? 'No approved, trust-confirmed clients are currently redirected to mitmdump'
          : `${ic} approved client${ic === 1 ? '' : 's'} redirected to mitmdump`;
      }
      if ($('hb-loss') && state.capture_stats) {
        const cs = state.capture_stats;
        const lost = cs.total_loss || 0;
        $('hb-loss').textContent = lost > 0 ? `${lost} lost` : '0 lost';
        $('hb-loss').className = lost > 0 ? 'state-warn' : '';
        $('hb-loss').title = `Observed: ${cs.observed || 0}, Retained: ${cs.retained || 0}, Filtered: ${cs.filtered || 0}, Evicted: ${cs.evicted || 0} (ring ${cs.evicted_ring || 0}, quota ${cs.evicted_quota || 0}), Queue drops: ${cs.dropped_queue || 0}, Stage drops: ${cs.dropped_stage || 0}, Worker errors: ${cs.worker_errors || 0}, IPC failures: ${cs.ipc_failures || 0}, Controller errors: ${cs.controller_errors || 0}${cs.last_error ? ' | Last: ' + cs.last_error : ''}`;
      }
      $('hb-last-poll').textContent = formatClock(new Date().toISOString(), false);
      $('hb-last-event').textContent = lastFlows.length ? formatClock(lastFlows[0].time, true) : 'None yet';
      if (!flowsPaused) {
        updateClientFilterOptions();
        renderFlows();
        saveInspectorCache();
      }
    } else {
      showView('admin');
      $('wan-state').textContent = state.wan_connected ? 'Connected' : 'Offline';
      $('client-count').textContent = state.clients.length;
      $('flow-count').textContent = `${(state.flows || []).length} / 100`;
      if (document.activeElement !== $('ssid')) $('ssid').value = state.ssid;
      const container = $('clients'); container.replaceChildren();
      if (!state.clients.length) {
        const p = document.createElement('p'); p.className = 'empty';
        p.textContent = state.monitor === 'ok'
          ? 'No wireless clients associated. Connect a test device to the NetBridge Wi-Fi network.'
          : 'Client monitoring is unavailable. Approvals have been cleared.';
        container.append(p);
      }
      for (const client of state.clients) {
        const row = document.createElement('article'); row.className = 'client';
        const info = document.createElement('div');
        const title = document.createElement('h3');
        const identity = document.createElement('p');
        const status = document.createElement('p');
        title.textContent = client.name;
        identity.textContent = `${client.ip || 'Waiting for DHCP'} · ${client.mac}`;
        status.className = 'client-state';
        if (client.approved) {
          status.textContent = state.inspection === 'on'
            ? 'APPROVED // full HTTP/HTTPS/TCP inspection active'
            : state.inspection === 'degraded'
              ? 'APPROVED // fail-open direct routing (proxy down)'
              : 'APPROVED // inspection remains off';
        } else {
          status.textContent = client.trust_confirmed
            ? 'TRUST CONFIRMED // awaiting operator approval'
            : client.downloaded
              ? 'CA DOWNLOADED // complete Step 02 trust probe'
              : 'ASSOCIATED // onboarding required';
        }
        info.append(title, identity, status);
        row.append(info);
        const button = document.createElement('button');
        button.textContent = client.approved ? 'Revoke approval' : 'Approve connection';
        button.disabled = !client.trust_confirmed;
        button.addEventListener('click', async () => {
          button.disabled = true;
          try { await api(client.approved ? 'revoke' : 'approve', { mac: client.mac }); await refreshProtected(); }
          catch (error) { notice(error.message, true); button.disabled = false; }
        });
        row.append(button);
        container.append(row);
      }
    }
  } finally {
    pollBusy = false;
  }
  scheduleRefresh();
}
async function loadTrustSection() {
  if (!secure) {
    $('trust-http-prompt').hidden = false;
    $('trust-https-box').hidden = true;
    $('launch-https-trust').href = `${httpsBase}/#trust-section`;
    return;
  }
  $('trust-http-prompt').hidden = true;
  $('trust-https-box').hidden = false;
  try {
    const result = await api('trust-probe');
    trustChallenge = result.challenge;
    $('trust-title').textContent = result.confirmed ? 'Browser trust already confirmed' : 'HTTPS endpoint validated cleanly';
    $('trust-copy').textContent = result.confirmed
      ? 'This browser is verified for the current Wi-Fi session. An operator can now approve this connection on Administration.'
      : 'If no certificate warning appeared and you did not click through an exception, confirm below.';
    $('trust-form').hidden = result.confirmed;
  } catch (error) {
    $('trust-title').textContent = 'Trust probe unavailable';
    $('trust-copy').textContent = error.message;
    $('trust-form').hidden = true;
  }
}
async function toggleInspection(button) {
  const enabling = inspectionState === 'off';
  button.disabled = true;
  clearTimeout(refreshTimer);
  try {
    notice(enabling ? 'Starting mitmdump inspection proxy…' : 'Stopping inspection proxy and flushing redirects…');
    const result = await api('inspection', { enabled: enabling });
    setInspectionState(result.inspection);
    notice(result.inspection === 'on'
      ? 'Inspection enabled for approved, trust-confirmed clients.'
      : 'Inspection disabled. Direct NAT routing restored.');
    await refreshProtected();
  } catch (error) {
    notice(error.message, true);
    await refreshProtected().catch(() => {});
  } finally {
    button.disabled = false;
  }
}
async function signOut() {
  try {
    await api('logout', {});
    clearTimeout(refreshTimer);
    clearInspectorCache();
    await clearBrowserArchive(true);
    if (authChannel) authChannel.postMessage({ type: 'invalidate', reason: 'logout' });
    showView('authentication');
    notice('Signed out.');
  } catch (error) {
    notice(error.message, true);
  }
}
function updateNavActiveState() {
  $('nav-setup').classList.toggle('is-active', isSetupPage());
  $('nav-admin').classList.toggle('is-active', isAdminPage());
  $('nav-inspector').classList.toggle('is-active', isInspectorPage());
}
function navigateSpa(targetPath) {
  if (!secure || targetPath === currentPath()) return false;
  if (targetPath !== '/admin' && targetPath !== '/inspector') return false;
  history.pushState({ path: targetPath }, '', targetPath);
  updateNavActiveState();
  refreshProtected().catch(error => {
    if (error.status === 401) {
      clearBrowserArchive(true);
      showView('authentication');
    } else {
      notice(error.message, true);
    }
  });
  return true;
}
async function init() {
  await cleanupOrphanedArchiveDbs();
  $('nav-admin').href = `${httpsBase}/admin`;
  $('nav-inspector').href = `${httpsBase}/inspector`;
  $('footer-admin').href = `${httpsBase}/admin`;
  $('footer-inspector').href = `${httpsBase}/inspector`;
  if ($('open-inspector-btn')) $('open-inspector-btn').href = `${httpsBase}/inspector`;
  updateNavActiveState();

  let info;
  try {
    info = await api('public');
    pairing = !info.paired;
    if (info.gateway) $('meta-gateway').textContent = info.gateway;
    setInspectionState(info.inspection);
    $('ca-name').textContent = info.ca.name;
    $('fingerprint').textContent = info.ca.fingerprint;
    $('ca-expiry').textContent = new Date(info.ca.expires).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
  } catch (error) {
    if (isInspectorPage() && loadInspectorCache()) {
      showOfflineCachedInspector(`Cardputer unreachable — viewing ${lastFlows.length} browser-cached flows from this tab.`);
      return;
    }
    notice(error.message, true);
    showView('setup');
    return;
  }

  if (isAdminPage() || isInspectorPage()) {
    $('auth-title').textContent = pairing ? 'Pair Administrator Account' : 'Operator Sign In';
    $('auth-submit').textContent = pairing ? 'Create administrator account' : 'Sign in';
    $('pair-field').hidden = !pairing;
    $('pair-code').required = pairing;
    if (pairing) {
      $('auth-copy').textContent = 'Enter the one-time pairing code displayed on the Cardputer screen, then choose a password (12+ characters).';
      $('admin-password').autocomplete = 'new-password';
    }
    try {
      await refreshProtected();
    } catch (error) {
      if (isInspectorPage() && error.status !== 401 && loadInspectorCache()) {
        showOfflineCachedInspector(`Cardputer unreachable — viewing ${lastFlows.length} browser-cached flows from this tab.`);
        return;
      }
      showView('authentication');
      if (error.status !== 401) notice(error.message, true);
    }
  } else {
    showView('setup');
    await loadTrustSection();
    if (currentPath() === '/trust' || location.hash === '#trust-section') {
      $('trust-section').scrollIntoView();
    }
  }
}

busy($('auth-form'), async () => {
  const data = { password: $('admin-password').value };
  if (pairing) data.code = $('pair-code').value.trim();
  await api(pairing ? 'pair' : 'login', data);
  $('admin-password').value = '';
  $('pair-code').value = '';
  pairing = false;
  notice('Authenticated.');
  await refreshProtected();
});
busy($('trust-form'), async () => {
  await api('trust-confirm', { challenge: trustChallenge, no_warning: $('no-warning').checked });
  $('trust-form').hidden = true;
  $('trust-title').textContent = 'Browser trust confirmed';
  $('trust-copy').textContent = 'This browser is verified for the current Wi-Fi session. Approve it on the Administration page.';
});
busy($('wifi-form'), async () => {
  if (!confirm('Restart the hotspot and disconnect all connected clients?')) return;
  const result = await api('ap-settings', { ssid: $('ssid').value, password: $('wifi-password').value });
  $('wifi-password').value = '';
  clearTimeout(refreshTimer);
  notice(result.message);
});
busy($('password-form'), async () => {
  await api('admin-password', { password: $('new-password').value });
  $('new-password').value = '';
  clearTimeout(refreshTimer);
  await clearBrowserArchive(true);
  if (authChannel) authChannel.postMessage({ type: 'invalidate', reason: 'password_changed' });
  showView('authentication');
  notice('Administrator password updated. Sign in again.');
});
busy($('rotate-form'), async () => {
  const result = await api('rotate-ca', { confirmation: $('rotate-confirm').value });
  clearTimeout(refreshTimer);
  await clearBrowserArchive(true);
  if (authChannel) authChannel.postMessage({ type: 'invalidate', reason: 'ca_rotated' });
  showView('setup');
  notice(result.message);
  setTimeout(() => { location.href = `http://${location.hostname}/`; }, 5000);
});

function sanitizeCsvCellClient(val) {
  if (typeof val !== 'string' || !val) return val;
  if ('=+-@\t\r'.includes(val[0]) || /^[ \t\r\n]*[=+\-@]/.test(val)) return `'${val}`;
  return val;
}
function csvEscapeClient(val) {
  const s = String(val ?? '');
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
async function downloadBrowserArchiveExport(meta) {
  if (meta.format === 'flow-hex' || meta.format === 'flow-raw') {
    const v = meta.view || {};
    let blobPart = '';
    let mime = 'application/octet-stream';
    let filename = `flow-${meta.flowId}-${meta.part}`;
    if (meta.format === 'flow-hex') {
      blobPart = v.hex || '';
      mime = 'text/plain; charset=utf-8';
      filename += '.hex';
    } else if (v.image_data_url && v.image_data_url.includes(',')) {
      const b64 = v.image_data_url.split(',', 2)[1];
      const bin = atob(b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
      blobPart = bytes;
      mime = v.content_type || 'application/octet-stream';
      filename += '.bin';
    } else if (v.text) {
      blobPart = v.text;
      mime = 'text/plain; charset=utf-8';
      filename += '.txt';
    } else {
      blobPart = v.hex || '';
      mime = 'text/plain; charset=utf-8';
      filename += '.hex';
    }
    const blob = new Blob([blobPart], { type: mime });
    const objUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = objUrl;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(objUrl), 5000);
    return;
  }
  const entriesList = await archiveGetAllDetails();
  if (!entriesList.length) {
    triggerExportDownload(meta.url);
    return;
  }
  const archiveMeta = {
    source: 'browser_archive',
    exported_at: new Date().toISOString(),
    device_id: archiveDeviceId,
    capture_session_id: archiveSessionId,
    archived_flows: archiveCount,
    missed_flows: archiveMissedCount,
    archive_bytes: archiveBytes,
    capture_stats: archiveLastCaptureStats || {},
  };
  let content = '', mime = 'application/octet-stream', filename = 'netbridge-capture.jsonl';
  if (meta.format === 'csv') {
    const header = ['id', 'time', 'client_ip', 'server_ip', 'server_port', 'method', 'scheme', 'host', 'path', 'status', 'content_type', 'req_bytes', 'resp_bytes', 'duration_ms', 'state', 'detail', 'payload_status'];
    const lines = [header.join(',')];
    for (const item of entriesList) {
      const d = item.detail;
      const m = d.flow;
      let row = [m.id, m.time || '', m.client_ip || '', m.server_ip || '', m.server_port || 0, m.method || '', m.scheme || '', m.host || '', m.path || '', m.status || 0, m.content_type || '', m.req_bytes || 0, m.bytes || 0, m.duration_ms || 0, m.state || '', m.detail || '', m.payload_status || ''];
      if (meta.safeCsv) row = row.map(v => typeof v === 'string' ? sanitizeCsvCellClient(v) : v);
      lines.push(row.map(csvEscapeClient).join(','));
    }
    content = lines.join('\r\n') + '\r\n';
    mime = 'text/csv; charset=utf-8';
    filename = meta.safeCsv ? 'netbridge-capture-safe.csv' : 'netbridge-capture.csv';
  } else if (meta.format === 'jsonl') {
    const lines = [JSON.stringify({ _netbridge_meta: true, ...archiveMeta })];
    for (const item of entriesList) {
      const d = item.detail;
      const rec = { ...d.flow };
      if (d.request && d.request.text) rec.request_text = d.request.text;
      if (d.response && d.response.text) rec.response_text = d.response.text;
      lines.push(JSON.stringify(rec));
    }
    content = lines.join('\n') + '\n';
    mime = 'application/x-ndjson; charset=utf-8';
    filename = 'netbridge-capture-archive.jsonl';
  } else if (meta.format === 'har') {
    const entries = [];
    let skipped = 0;
    for (const item of entriesList) {
      const d = item.detail;
      const m = d.flow;
      const scheme = (m.scheme || 'http').toLowerCase();
      if ((m.state !== 'decrypted' && m.state !== 'passthrough') || (scheme !== 'http' && scheme !== 'https')) {
        skipped += 1;
        continue;
      }
      const defPort = scheme === 'https' ? 443 : 80;
      const portPart = m.server_port && m.server_port !== defPort ? `:${m.server_port}` : '';
      const url = m.host ? `${scheme}://${m.host}${portPart}${m.path || '/'}` : (m.path || '/');
      entries.push({
        startedDateTime: m.time || '',
        time: m.duration_ms || 0,
        request: {
          method: m.method || 'GET',
          url,
          httpVersion: m.http_version || 'HTTP/1.1',
          headers: (m.request_headers || []).map(([name, value]) => ({ name, value })),
          queryString: [],
          cookies: [],
          headersSize: -1,
          bodySize: m.req_bytes || 0,
          ...(d.request && d.request.text ? { postData: { mimeType: m.req_content_type || 'text/plain', text: d.request.text } } : {}),
        },
        response: {
          status: m.status || 0,
          statusText: m.reason || '',
          httpVersion: m.resp_http_version || 'HTTP/1.1',
          headers: (m.response_headers || []).map(([name, value]) => ({ name, value })),
          cookies: [],
          content: { size: m.bytes || 0, mimeType: m.content_type || 'application/octet-stream', ...(d.response && d.response.text ? { text: d.response.text } : {}) },
          redirectURL: '',
          headersSize: -1,
          bodySize: m.bytes || 0,
        },
        cache: {},
        timings: { blocked: -1, dns: -1, connect: -1, ssl: -1, send: -1, wait: m.duration_ms || 0, receive: -1 },
        serverIPAddress: m.server_ip || '',
        _netbridge: { flow_id: m.id, state: m.state, payload_status: m.payload_status || '' },
      });
    }
    content = JSON.stringify({ log: { version: '1.2', creator: { name: 'NetBridge', version: '1.0' }, entries, _netbridge: { ...archiveMeta, included_entries: entries.length, skipped_non_http: skipped } } }, null, 2);
    mime = 'application/json; charset=utf-8';
    filename = 'netbridge-capture-archive.har';
  }
  const blob = new Blob([content], { type: mime });
  const objUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = objUrl;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(objUrl), 5000);
}
function triggerExportDownload(url) {
  const sep = url.includes('?') ? '&' : '?';
  const confirmedUrl = url.includes('confirm=') ? url : `${url}${sep}confirm=unredacted`;
  const link = document.createElement('a');
  link.href = confirmedUrl;
  link.download = '';
  document.body.append(link);
  link.click();
  link.remove();
}
function requestExportConfirmation(url, label, archiveMeta = null) {
  const dialog = $('export-confirm-dialog');
  const extra = label === 'CSV (Raw)'
    ? ' Raw CSV preserves untrusted cell values verbatim without spreadsheet formula escaping.'
    : '';
  const scopeNote = archiveMeta && archiveCount > 0 ? ` (Browser Archive: ${archiveCount} flows)` : '';
  if (!dialog || typeof dialog.showModal !== 'function') {
    if (confirm(`Plain-text export warning: ${label}${scopeNote} exports are unredacted and can expose sensitive information such as tokens, cookies, or credentials.${extra} Continue?`)) {
      if (archiveMeta && archiveCount > 0) downloadBrowserArchiveExport(archiveMeta);
      else triggerExportDownload(url);
    }
    return;
  }
  pendingExportUrl = url;
  pendingExportMeta = archiveMeta && archiveCount > 0 ? archiveMeta : null;
  $('export-confirm-title').textContent = `Export unredacted ${label}${scopeNote}?`;
  $('export-confirm-proceed').textContent = `Export ${label}`;
  if ($('export-confirm-copy')) {
    $('export-confirm-copy').textContent = `NetBridge logs are unredacted plain text. Exporting can expose sensitive information such as authentication tokens, session cookies, API keys, passwords, or private payloads.${extra} Confirm that you want to download this file.`;
  }
  dialog.showModal();
}

$('admin-toggle-inspection').addEventListener('click', () => toggleInspection($('admin-toggle-inspection')));
$('inspector-toggle-inspection').addEventListener('click', () => toggleInspection($('inspector-toggle-inspection')));
if ($('toggle-browser-archive')) $('toggle-browser-archive').addEventListener('click', startOrResumeBrowserArchive);
if ($('archive-pause-btn')) $('archive-pause-btn').addEventListener('click', startOrResumeBrowserArchive);
if ($('archive-export-btn')) {
  $('archive-export-btn').addEventListener('click', () => {
    requestExportConfirmation('/api/flows-export?format=jsonl', 'JSONL', {
      url: '/api/flows-export?format=jsonl',
      format: 'jsonl',
      safeCsv: false,
    });
  });
}
if ($('archive-limit-select')) {
  $('archive-limit-select').addEventListener('change', () => {
    const val = parseInt($('archive-limit-select').value, 10);
    if (Number.isFinite(val) && val > 0) {
      archiveLimitBytes = val;
      if (archivePausedReason === 'limit' && archiveBytes < archiveLimitBytes) {
        archivePausedReason = 'manual';
      }
      updateArchiveBanner();
    }
  });
}
if ($('archive-clear-btn')) $('archive-clear-btn').addEventListener('click', () => clearBrowserArchive(false));
for (const [elId, targetPath] of [
  ['nav-admin', '/admin'],
  ['nav-inspector', '/inspector'],
  ['footer-admin', '/admin'],
  ['footer-inspector', '/inspector'],
  ['open-inspector-btn', '/inspector'],
]) {
  const link = $(elId);
  if (link) {
    link.addEventListener('click', event => {
      if (secure && (isAdminPage() || isInspectorPage()) && navigateSpa(targetPath)) {
        event.preventDefault();
      }
    });
  }
}
window.addEventListener('popstate', () => {
  if (!secure) return;
  updateNavActiveState();
  if (isAdminPage() || isInspectorPage()) {
    refreshProtected().catch(() => {});
  } else {
    showView('setup');
  }
});
window.addEventListener('pageshow', event => {
  if (event.persisted) {
    clearBrowserArchive(true);
  }
});
if (authChannel) {
  authChannel.addEventListener('message', event => {
    if (event.data && event.data.type === 'invalidate') {
      clearTimeout(refreshTimer);
      clearInspectorCache();
      clearBrowserArchive(true);
      showView('authentication');
      notice('Session invalidated in another tab; browser archive cleared.');
    }
  });
}
for (const evtName of ['pointerdown', 'keydown', 'click']) {
  document.addEventListener(evtName, () => touchArchiveActivity(false), { passive: true });
}
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) checkArchiveExpiry();
});
setInterval(() => {
  checkArchiveExpiry().then(expired => {
    if (!expired && (archiveEnabled || archiveCount > 0)) updateArchiveBanner();
  });
}, 15000);
window.addEventListener('beforeunload', event => {
  if (archiveCount > 0) {
    event.preventDefault();
    event.returnValue = '';
  }
});
for (const [id, label, fmt, safeCsv] of [
  ['export-jsonl', 'JSONL', 'jsonl', false],
  ['export-har', 'HAR', 'har', false],
  ['export-csv-safe', 'CSV (Safe)', 'csv', true],
  ['export-csv', 'CSV (Raw)', 'csv', false],
]) {
  const el = $(id);
  if (el) {
    el.addEventListener('click', event => {
      event.preventDefault();
      requestExportConfirmation(el.href, label, { url: el.href, format: fmt, safeCsv });
    });
  }
}
if ($('export-confirm-cancel')) {
  $('export-confirm-cancel').addEventListener('click', () => {
    pendingExportUrl = null;
    pendingExportMeta = null;
    $('export-confirm-dialog').close();
  });
}
if ($('export-confirm-proceed')) {
  $('export-confirm-proceed').addEventListener('click', () => {
    const url = pendingExportUrl;
    const meta = pendingExportMeta;
    pendingExportUrl = null;
    pendingExportMeta = null;
    $('export-confirm-dialog').close();
    if (meta) downloadBrowserArchiveExport(meta).catch(err => notice(err.message, true));
    else if (url) triggerExportDownload(url);
  });
}
if ($('export-confirm-dialog')) {
  const dialog = $('export-confirm-dialog');
  dialog.addEventListener('cancel', () => { pendingExportUrl = null; pendingExportMeta = null; });
  dialog.addEventListener('click', event => {
    if (event.target === dialog) {
      pendingExportUrl = null;
      pendingExportMeta = null;
      dialog.close();
    }
  });
}
$('pause-flows').addEventListener('click', () => {
  flowsPaused = !flowsPaused;
  $('pause-flows').textContent = flowsPaused ? 'Resume' : 'Pause';
  $('pause-flows').className = flowsPaused ? 'primary' : 'quiet';
  setInspectionState(inspectionState);
  if (!flowsPaused) refreshProtected().catch(error => notice(error.message, true));
});
$('clear-flows').addEventListener('click', async () => {
  try {
    await api('flows-clear', {});
    lastFlows = []; selectedFlowId = null; selectedDetail = null;
    clearInspectorCache();
    archiveHighWaterId = 0;
    archiveSessionId = '';
    clearDeepSearch(false);
    $('inspector-content').hidden = true; $('inspector-empty').hidden = false;
    $('hb-flows').textContent = '0 / 100';
    $('hb-last-event').textContent = 'Cleared';
    renderFlows();
    notice(archiveCount > 0
      ? 'Cleared device capture ring (encrypted browser archive preserved).'
      : 'Cleared device capture ring.');
  } catch (error) {
    notice(error.message, true);
  }
});
for (const tabBtn of document.querySelectorAll('.inspector-tabs .tab')) {
  tabBtn.addEventListener('click', () => { activeTab = tabBtn.dataset.tab; renderInspector(); });
}
$('inspector-close').addEventListener('click', () => {
  selectedFlowId = null; selectedDetail = null;
  $('inspector-content').hidden = true; $('inspector-empty').hidden = false;
  renderFlows();
});
$('filter-client').addEventListener('change', renderFlows);
$('filter-host').addEventListener('input', renderFlows);
$('filter-state').addEventListener('change', renderFlows);

async function saveCaptureFilters() {
  const categories = Array.from(document.querySelectorAll('#ingest-bar input[data-ingest]:checked'))
    .map(el => el.dataset.ingest);
  const host_filter = $('ingest-host') ? $('ingest-host').value.trim() : '';
  const skip_noise = $('ingest-skip-noise') ? $('ingest-skip-noise').checked : false;
  filterSaveBusy = true;
  try {
    const result = await api('capture-filters', { categories, host_filter, skip_noise });
    const count = (result.capture_filters || categories).length;
    const parts = [`${count}/8 categories`];
    if (result.capture_skip_noise) parts.push('noise skipped');
    if (result.capture_host_filter) parts.push(`host: ${result.capture_host_filter}`);
    notice(`Capture ingest updated (${parts.join(' · ')}).`);
  } catch (error) {
    notice(error.message, true);
  } finally {
    filterSaveBusy = false;
  }
}

for (const cb of document.querySelectorAll('#ingest-bar input[data-ingest]')) {
  cb.addEventListener('change', saveCaptureFilters);
}
if ($('ingest-skip-noise')) {
  $('ingest-skip-noise').addEventListener('change', saveCaptureFilters);
}
if ($('ingest-all')) {
  $('ingest-all').addEventListener('click', () => {
    for (const cb of document.querySelectorAll('#ingest-bar input[data-ingest]')) cb.checked = true;
    saveCaptureFilters();
  });
}
if ($('ingest-none')) {
  $('ingest-none').addEventListener('click', () => {
    for (const cb of document.querySelectorAll('#ingest-bar input[data-ingest]')) cb.checked = false;
    saveCaptureFilters();
  });
}
if ($('ingest-host-apply')) {
  $('ingest-host-apply').addEventListener('click', saveCaptureFilters);
}
if ($('ingest-host')) {
  $('ingest-host').addEventListener('keydown', event => {
    if (event.key === 'Enter') {
      event.preventDefault();
      saveCaptureFilters();
    }
  });
}

function clearDeepSearch(rerender = true) {
  deepSearchMatchMap = null;
  if ($('deep-search-input')) $('deep-search-input').value = '';
  if ($('deep-search-clear')) $('deep-search-clear').hidden = true;
  if ($('deep-search-status')) {
    $('deep-search-status').hidden = true;
    $('deep-search-status').textContent = '';
  }
  if (rerender) renderFlows();
}

async function runDeepSearch() {
  const q = $('deep-search-input') ? $('deep-search-input').value.trim() : '';
  if (!q) {
    clearDeepSearch(true);
    return;
  }
  const btn = $('deep-search-btn');
  if (btn) btn.disabled = true;
  try {
    const map = new Map();
    if (archiveCount > 0) {
      const needle = q.toLowerCase();
      const entriesList = await archiveGetAllDetails();
      for (const item of entriesList) {
        const d = item.detail;
        const m = d.flow || {};
        const where = [];
        const urlBlob = `${m.method || ''} ${m.scheme || ''} ${m.host || ''} ${m.path || ''} ${m.detail || ''} ${m.server_ip || ''}`.toLowerCase();
        if (urlBlob.includes(needle)) where.push('url');
        if ((m.request_headers || []).some(([k, v]) => `${k} ${v}`.toLowerCase().includes(needle))) where.push('req_header');
        if ((m.response_headers || []).some(([k, v]) => `${k} ${v}`.toLowerCase().includes(needle))) where.push('resp_header');
        if (d.request && d.request.text && d.request.text.toLowerCase().includes(needle)) where.push('req_body');
        if (d.response && d.response.text && d.response.text.toLowerCase().includes(needle)) where.push('resp_body');
        if (where.length) map.set(m._archiveKey || item.key, where);
      }
    }
    const result = await api(`flows-search?q=${encodeURIComponent(q)}`);
    for (const m of (result.matches || [])) {
      if (!map.has(m.id)) map.set(m.id, m.where || []);
    }
    deepSearchMatchMap = map;
    if ($('deep-search-clear')) $('deep-search-clear').hidden = false;
    if ($('deep-search-status')) {
      $('deep-search-status').hidden = false;
      $('deep-search-status').textContent = `Deep search "${result.query}": ${map.size} match${map.size === 1 ? '' : 'es'}`;
    }
    renderFlows();
  } catch (error) {
    notice(error.message, true);
  } finally {
    if (btn) btn.disabled = false;
  }
}

if ($('deep-search-btn')) $('deep-search-btn').addEventListener('click', runDeepSearch);
if ($('deep-search-clear')) $('deep-search-clear').addEventListener('click', () => clearDeepSearch(true));
if ($('deep-search-input')) {
  $('deep-search-input').addEventListener('keydown', event => {
    if (event.key === 'Enter') {
      event.preventDefault();
      runDeepSearch();
    }
  });
}
$('admin-logout').addEventListener('click', signOut);
$('inspector-logout').addEventListener('click', signOut);
$('admin-refresh').addEventListener('click', () => refreshProtected().catch(error => notice(error.message, true)));
init();
