/* Flowers.ae internal app — shared login + per-user storage
   Security: real per-person accounts via Supabase Auth (email + password,
   @flowers.ae addresses only, enforced by the database itself), roles
   stored server-side in `profiles` and checked by the database — not just
   hidden in the UI. Auto-logout after inactivity, activity log. */
const FLApp = (() => {
  const SESSION_KEY = 'fl_session';
  const ACTIVITY_KEY = 'fl_last_activity';
  const LOG_KEY = 'fl_activity_log';
  const MAILQ_KEY = 'fl_mailq';

  const IDLE_LOGOUT_MINUTES = 30;
  const IDLE_LOGOUT_MINUTES_CEO = 90 * 24 * 60; // CEO stays logged in ~3 months on her own devices

  /* ── EmailJS config (unused for auth now — Supabase sends those emails
     directly — kept here only for any other custom alerts later). */
  const EMAILJS = {
    publicKey: '',
    serviceId: '',
    templateId: ''
  };

  function session() { try { return JSON.parse(localStorage.getItem(SESSION_KEY) || 'null'); } catch (e) { return null; } }
  function saveSession(s) { localStorage.setItem(SESSION_KEY, JSON.stringify(s)); }
  function clearSession() { localStorage.removeItem(SESSION_KEY); }

  /* remembers who has logged in/registered on THIS device, so the login
     screen can suggest an email as soon as you type its first letter —
     just this device's own history, never fetched from the server (the
     login page is pre-auth, so it has no access to the team roster). */
  const KNOWN_KEY = 'fl_known_accounts';
  function rememberKnownAccount(email, name) {
    email = (email || '').trim().toLowerCase();
    if (!email) return;
    try {
      const list = JSON.parse(localStorage.getItem(KNOWN_KEY) || '[]').filter(a => a.email !== email);
      list.unshift({ email, name: name || email });
      localStorage.setItem(KNOWN_KEY, JSON.stringify(list.slice(0, 12)));
    } catch (e) {}
  }
  function knownAccounts() {
    try { return JSON.parse(localStorage.getItem(KNOWN_KEY) || '[]'); } catch (e) { return []; }
  }

  function checkPasswordStrength(pw) {
    if (pw.length < 6) throw new Error('Password must be at least 6 characters');
    if (!/[0-9]/.test(pw)) throw new Error('Password must contain at least one number');
    if (!/[a-zA-Z]/.test(pw)) throw new Error('Password must contain at least one letter');
  }

  async function fetchProfile(userId, token) {
    const res = await fetchT(SYNC.url + '/rest/v1/profiles?id=eq.' + userId + '&select=*', {
      headers: { apikey: SYNC.key, Authorization: 'Bearer ' + token }
    });
    if (!res.ok) return null;
    const rows = await res.json();
    return rows[0] || null;
  }

  async function afterAuth(tokenBody, fallbackName) {
    const profile = await fetchProfile(tokenBody.user.id, tokenBody.access_token) ||
      { name: fallbackName || tokenBody.user.email, role: 'staff', email: tokenBody.user.email, disabled: false };
    if (profile.disabled) throw new Error('This account has been disabled — contact your admin.');
    saveSession({
      access_token: tokenBody.access_token,
      refresh_token: tokenBody.refresh_token,
      expires_at: Date.now() + (tokenBody.expires_in || 3600) * 1000,
      user: { id: tokenBody.user.id, email: tokenBody.user.email },
      profile
    });
    localStorage.setItem(ACTIVITY_KEY, String(Date.now()));
    rememberKnownAccount(tokenBody.user.email, profile.name);
  }

  /* self-service sign-up — @flowers.ae only, enforced by the database trigger
     (not just this check) — you choose your own password, confirm your email,
     then log in. New accounts start as 'staff'; an admin promotes from there. */
  async function register(name, email, password) {
    name = (name || '').trim();
    email = (email || '').trim().toLowerCase();
    password = (password || '').trim();
    if (!name) throw new Error('Please enter your name');
    if (!/@flowers\.ae$/i.test(email)) throw new Error('Please use your @flowers.ae email address');
    checkPasswordStrength(password);
    const res = await fetchT(SYNC.url + '/auth/v1/signup', {
      method: 'POST',
      headers: { apikey: SYNC.key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, data: { name } })
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.msg || body.message || 'Could not create account');
    if (!body.access_token) return { pendingConfirmation: true };  /* must confirm email first */
    await afterAuth(body, name);
    recordEvent('New account created', name);
    return { pendingConfirmation: false };
  }

  /* confirms a brand-new signup using the code emailed to them
     (instead of making them click a link) — then logs them straight in */
  async function confirmSignup(email, code) {
    email = (email || '').trim().toLowerCase();
    const res = await fetchT(SYNC.url + '/auth/v1/verify', {
      method: 'POST',
      headers: { apikey: SYNC.key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'signup', email, token: (code || '').trim() })
    });
    const body = await res.json();
    if (!res.ok) throw new Error('That code is wrong or expired');
    await afterAuth(body);
    recordEvent('New account created', currentUser().name);
  }

  async function login(email, password) {
    email = (email || '').trim().toLowerCase();
    password = (password || '').trim();
    const res = await fetchT(SYNC.url + '/auth/v1/token?grant_type=password', {
      method: 'POST',
      headers: { apikey: SYNC.key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const body = await res.json();
    if (!res.ok) {
      if (body.error_code === 'email_not_confirmed') throw new Error('Please confirm your email first — check your inbox.');
      throw new Error('Wrong email or password');
    }
    await afterAuth(body);
    recordEvent('Logged in', currentUser().name);
    return currentUser();
  }

  function logout() {
    const s = session();
    clearSession();
    if (s && s.access_token) {
      fetchT(SYNC.url + '/auth/v1/logout', { method: 'POST', headers: { apikey: SYNC.key, Authorization: 'Bearer ' + s.access_token } }).catch(() => {});
    }
    location.href = 'index.html';
  }

  function currentUser() {
    const s = session();
    if (!s) return null;
    return {
      id: s.user.id, email: s.user.email,
      name: (s.profile && s.profile.name) || s.user.email,
      role: (s.profile && s.profile.role) || 'staff',
      disabled: !!(s.profile && s.profile.disabled)
    };
  }

  /* refreshes the access token if it's expired/near-expiry; if that fails
     (offline, or the refresh token itself expired) it just keeps using the
     cached identity — offline-first, never force a logout just for being
     offline. Also re-pulls the profile so a role change by an admin shows
     up without waiting for the person to log out and back in. */
  async function ensureFreshToken() {
    const s = session();
    if (!s) return null;
    if (Date.now() < s.expires_at - 60000) return s.access_token;
    try {
      const res = await fetchT(SYNC.url + '/auth/v1/token?grant_type=refresh_token', {
        method: 'POST',
        headers: { apikey: SYNC.key, 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: s.refresh_token })
      });
      const body = await res.json();
      if (!res.ok) return s.access_token;
      s.access_token = body.access_token;
      s.refresh_token = body.refresh_token;
      s.expires_at = Date.now() + (body.expires_in || 3600) * 1000;
      const fresh = await fetchProfile(s.user.id, s.access_token);
      if (fresh) s.profile = fresh;
      saveSession(s);
      return s.access_token;
    } catch (e) { return s.access_token; }
  }

  /* ── Roles ───────────────────────────────────────────────
     admin   = full control (Sajith): admin panel, price edits, events
     finance = events/GP module + the other tools (accountant)
     ceo     = Event GP Sheets ONLY — sees nothing else
     staff   = calculator + timelines only
     Enforced server-side (see admin_set_role / RLS) — these functions
     just reflect what the database already decided, for the UI. */
  function role(u) { return (u && u.role) || 'staff'; }
  function isAdmin() { return role(currentUser()) === 'admin'; }
  function canFinance() { return ['admin', 'finance', 'ceo'].includes(role(currentUser())); }
  function isCeo() { return role(currentUser()) === 'ceo'; }

  /* the database itself checks the caller is really an admin before
     allowing either of these — see admin_set_role / admin_set_disabled */
  async function adminSetRole(userId, newRole) {
    const token = await ensureFreshToken();
    const res = await fetchT(SYNC.url + '/rest/v1/rpc/admin_set_role', {
      method: 'POST',
      headers: { apikey: SYNC.key, Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_user: userId, new_role: newRole })
    });
    if (!res.ok) { const b = await res.json().catch(() => ({})); throw new Error(b.message || 'Could not change role'); }
    recordEvent('Role changed to ' + newRole + ' (by ' + currentUser().name + ')', userId);
  }

  async function adminSetDisabled(userId, disabled) {
    const token = await ensureFreshToken();
    const res = await fetchT(SYNC.url + '/rest/v1/rpc/admin_set_disabled', {
      method: 'POST',
      headers: { apikey: SYNC.key, Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_user: userId, is_disabled: disabled })
    });
    if (!res.ok) { const b = await res.json().catch(() => ({})); throw new Error(b.message || 'Could not update account'); }
    recordEvent((disabled ? 'Account disabled' : 'Account re-enabled') + ' (by ' + currentUser().name + ')', userId);
  }

  /* permanently deletes an account — unlike adminSetDisabled, this cannot
     be undone. The database checks the caller is really an admin, and
     blocks deleting your own account, regardless of what the app sends. */
  async function adminDeleteUser(userId, name) {
    const token = await ensureFreshToken();
    const res = await fetchT(SYNC.url + '/rest/v1/rpc/admin_delete_user', {
      method: 'POST',
      headers: { apikey: SYNC.key, Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_user: userId })
    });
    if (!res.ok) { const b = await res.json().catch(() => ({})); throw new Error(b.message || 'Could not delete account'); }
    recordEvent('Account deleted: ' + (name || userId) + ' (by ' + currentUser().name + ')', name || userId);
  }

  /* every real team account — any logged-in person can see the list
     (needed for the admin panel), but only admin_set_role/_disabled can
     change one, and those check the caller server-side. */
  async function fetchAllProfiles() {
    const token = await ensureFreshToken();
    const res = await fetchT(SYNC.url + '/rest/v1/profiles?select=*&order=created_at.asc', {
      headers: { apikey: SYNC.key, Authorization: 'Bearer ' + (token || SYNC.key) }
    });
    if (!res.ok) throw new Error('Could not load team accounts');
    return res.json();
  }

  /* forgot password: email → 6-digit code → new password, all self-service */
  async function requestPasswordReset(email) {
    email = (email || '').trim().toLowerCase();
    await fetchT(SYNC.url + '/auth/v1/recover', {
      method: 'POST',
      headers: { apikey: SYNC.key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    }).catch(() => {});
    /* always resolves the same way regardless of whether the email exists — normal practice, doesn't reveal who has an account */
  }

  async function confirmPasswordReset(email, code, newPassword) {
    email = (email || '').trim().toLowerCase();
    newPassword = (newPassword || '').trim();
    checkPasswordStrength(newPassword);
    const res = await fetchT(SYNC.url + '/auth/v1/verify', {
      method: 'POST',
      headers: { apikey: SYNC.key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'recovery', email, token: (code || '').trim() })
    });
    const body = await res.json();
    if (!res.ok) throw new Error('That code is wrong or expired');
    const res2 = await fetchT(SYNC.url + '/auth/v1/user', {
      method: 'PUT',
      headers: { apikey: SYNC.key, Authorization: 'Bearer ' + body.access_token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: newPassword })
    });
    if (!res2.ok) throw new Error('Could not set new password');
    await afterAuth(body);
    recordEvent('Password reset', currentUser().name);
  }

  let idleListenersArmed = false;
  function guard() {
    if (!currentUser()) { location.replace('index.html'); return; }
    const last = parseInt(localStorage.getItem(ACTIVITY_KEY) || '0');
    const idleLimit = isCeo() ? IDLE_LOGOUT_MINUTES_CEO : IDLE_LOGOUT_MINUTES;
    if (Date.now() - last > idleLimit * 60000) {
      clearSession();
      location.replace('index.html');
      return;
    }
    localStorage.setItem(ACTIVITY_KEY, String(Date.now()));
    ensureFreshToken();
    if (!idleListenersArmed) {
      idleListenersArmed = true;
      let lastTouch = Date.now();
      ['pointerdown', 'keydown'].forEach(ev =>
        document.addEventListener(ev, () => {
          if (Date.now() - lastTouch > 30000) {
            lastTouch = Date.now();
            localStorage.setItem(ACTIVITY_KEY, String(lastTouch));
          }
        }, { passive: true })
      );
    }
  }

  function guardRole(roles) {
    guard();
    const u = currentUser();
    if (u && !roles.includes(role(u))) location.replace('home.html');
  }

  /* ── Big-value store ─────────────────────────────────────────
     localStorage is capped at ~5MB per app by the browser, and on Android
     that limit is enforced hard. Invoice photos live inside `fl_events`,
     which reached 4.6MB by Aug 2026 and pushed the total over the line —
     every write then threw QuotaExceededError, which crashed syncNow()
     midway (after the download, before the upload). The tablet silently
     stopped uploading anything and just reported "offline".

     IndexedDB has no such cap (hundreds of MB), so the events blob lives
     there instead. Deliberately kept byte-identical — same JSON, same
     shape — so nothing about syncing, Supabase, or other devices changes;
     only where this one device parks the bytes.

     The app's accessors are synchronous and IndexedDB is not, so until the
     migration finishes reads and writes carry on against localStorage
     exactly as before. That keeps the changeover safe: there is no window
     where a read returns less than the whole truth. If IndexedDB is
     unavailable for any reason, `bigReady` never flips and the app behaves
     exactly as it does today. */
  const BIG_KEYS = ['fl_events'];
  const bigCache = {};
  let bigReady = false;      /* IndexedDB loaded — the cache is the truth */
  let bigSettled = false;    /* the attempt has FINISHED, success or failure */
  let idb = null;
  let readyQueue = [];

  /* Run cb once the store can actually answer. This exists because the very
     first version of this shipped a read that could return "nothing" while
     IndexedDB was still opening — and a page that asks at that instant (the
     event editor asks on line 1) drew an empty form over a real event, then
     let it be saved back as blank. Sep 2026. Anything that reads or writes
     event data at page load must go through here. */
  function whenReady(cb) {
    if (bigSettled) { cb(); return; }
    readyQueue.push(cb);
  }
  function flushReady() {
    bigSettled = true;
    const q = readyQueue; readyQueue = [];
    q.forEach(cb => { try { cb(); } catch (e) {} });
    /* wake every page that already refreshes itself on sync, so anything
       drawn during the gap is redrawn against the real data */
    try { emitSync('synced'); } catch (e) {}
  }

  function idbOpen() {
    return new Promise((res, rej) => {
      if (!self.indexedDB) return rej(new Error('no indexedDB'));
      const rq = indexedDB.open('fl_store', 1);
      rq.onupgradeneeded = () => { rq.result.createObjectStore('kv'); };
      rq.onsuccess = () => res(rq.result);
      rq.onerror = () => rej(rq.error);
    });
  }
  function idbGet(key) {
    return new Promise((res, rej) => {
      const rq = idb.transaction('kv', 'readonly').objectStore('kv').get(key);
      rq.onsuccess = () => res(rq.result);
      rq.onerror = () => rej(rq.error);
    });
  }
  function idbPut(key, val) {
    return new Promise((res, rej) => {
      const tx = idb.transaction('kv', 'readwrite');
      tx.objectStore('kv').put(val, key);
      tx.oncomplete = () => res(true);
      tx.onerror = () => rej(tx.error);
      tx.onabort = () => rej(tx.error);
    });
  }

  /* The photos are what made this blob too big — the records themselves are
     tiny (~0.1MB for 90 events). So localStorage keeps a COMPLETE list with
     the photo bytes swapped for a marker, and IndexedDB keeps the real thing.
     A read before IndexedDB has opened therefore returns every event, just
     without photo pixels — never an empty list. That distinction matters:
     "no events" got drawn over real sheets and autosaved back as blank. */
  const PHOTO_MARK = '__fl_photo__';
  function stripPhotos(json) {
    try {
      return JSON.stringify(JSON.parse(json), (k, v) =>
        (typeof v === 'string' && v.slice(0, 5) === 'data:') ? PHOTO_MARK : v);
    } catch (e) { return json; }
  }
  /* walk a record and put the real photo back wherever a marker survived */
  function restorePhotos(target, source) {
    if (target === PHOTO_MARK) return typeof source === 'string' ? source : target;
    if (Array.isArray(target)) return target.map((v, i) => restorePhotos(v, source && source[i]));
    if (target && typeof target === 'object') {
      const out = {};
      for (const k in target) out[k] = restorePhotos(target[k], source && source[k]);
      return out;
    }
    return target;
  }
  function hasPhotoMark(obj) { return JSON.stringify(obj).indexOf(PHOTO_MARK) !== -1; }
  /* A page that opened before the photo store finished loading is holding
     markers where images should be — its thumbnails render broken. Call this
     once the store is ready to get the same record with real images back. */
  function hydratePhotos(rec) {
    if (!rec || !hasPhotoMark(rec)) return rec;
    const stored = eventsAll().find(x => x.id === rec.id);
    return stored ? restorePhotos(rec, stored) : rec;
  }

  function bigGet(key) {
    if (bigReady && key in bigCache) return bigCache[key];
    return localStorage.getItem(key);   /* the photo-free mirror — complete list */
  }
  function writeLite(key, val) {
    try { localStorage.setItem(key, stripPhotos(val)); }
    catch (e) { reportStorageProblem(e); }
  }
  function bigSet(key, val) {
    if (bigReady && key in bigCache) {
      bigCache[key] = val;
      idbPut(key, val).catch(() => reportStorageProblem());
      writeLite(key, val);
      return;
    }
    try { localStorage.setItem(key, val); }
    catch (e) { reportStorageProblem(e); throw e; }
  }

  async function initBigStore() {
    try {
      idb = await idbOpen();
      for (const key of BIG_KEYS) {
        const ls = localStorage.getItem(key);
        /* a mirror is recognisable: its photos are markers, not real bytes.
           Never mistake the mirror for the original, or writing it back to
           IndexedDB would wipe every photo. */
        const lsIsMirror = ls !== null && ls.indexOf(PHOTO_MARK) !== -1;
        let full = await idbGet(key);

        if (full === undefined || (ls !== null && !lsIsMirror)) {
          /* either the first run after this release (localStorage still holds
             the real thing), or a session where IndexedDB was unavailable and
             the full copy went to localStorage — either way that copy is the
             newer work and wins */
          if (ls !== null) { await idbPut(key, ls); full = ls; }
        }
        if (full === undefined) full = null;

        bigCache[key] = full;
        /* shrink localStorage to the photo-free mirror: complete list, tiny */
        if (full !== null) writeLite(key, full);
      }
      bigReady = true;
    } catch (e) {
      bigReady = false;   /* stay on localStorage — no worse than before */
    } finally {
      /* settle either way: if IndexedDB is unavailable the app must carry on
         against localStorage rather than wait forever for a reader that will
         never arrive */
      flushReady();
    }
  }

  /* A device that cannot save has to SAY so. Until Sep 2026 this surfaced as
     "offline", which sent everyone hunting for a network fault while the real
     cause was a full device — it cost a day to find. */
  let storageProblem = false;
  function reportStorageProblem(err) {
    storageProblem = true;
    try { emitSync('storage-full'); } catch (e) {}
    if (typeof document === 'undefined' || !document.body) return;
    if (document.getElementById('fl-storage-banner')) return;
    const el = document.createElement('div');
    el.id = 'fl-storage-banner';
    el.innerHTML =
      '<div style="position:fixed;top:0;left:0;right:0;z-index:9998;background:linear-gradient(135deg,#F4E0E0,#E9C9C9);padding:12px 14px;display:flex;align-items:center;gap:12px;box-shadow:0 6px 24px rgba(75,13,36,.35);font-family:Lato,Arial,sans-serif;">' +
      '<span style="font-size:19px;">⚠</span>' +
      '<span style="flex:1;min-width:0;"><b style="color:#8f1d1d;font-size:13px;">This device is out of storage space</b><br>' +
      '<span style="color:#7a3b3b;font-size:11px;">It cannot save, so nothing entered here is reaching the other devices. Tell Sajith.</span></span>' +
      '<button id="fl-storage-x" style="background:none;border:none;color:#7a3b3b;font-size:16px;cursor:pointer;padding:6px;">✕</button></div>';
    document.body.appendChild(el);
    const x = document.getElementById('fl-storage-x');
    if (x) x.onclick = () => el.remove();
  }
  function storageIsFull() { return storageProblem; }

  /* ── Shared event GP sheets (admin + finance only) ───────── */
  const EVENTS_KEY = 'fl_events';
  function eventsAll() { return JSON.parse(bigGet(EVENTS_KEY) || '[]'); }
  /* true only when eventsAll() is telling the whole truth. Anything that would
     WRITE based on a read must check this, or an early empty read gets saved
     back over real data. */
  function eventsLoaded() { return bigSettled; }
  function eventGet(id) { return eventsAll().find(x => x.id === id) || null; }
  function eventSave(ev) {
    /* never merge into a list we haven't finished loading — that is how a
       blank form overwrote a real event. Defer instead of guessing. */
    if (!bigSettled) { whenReady(() => eventSave(ev)); return; }
    const all = eventsAll();
    /* a page that loaded during the gap holds photo markers rather than
       photos; put the real ones back before this is written anywhere */
    if (hasPhotoMark(ev)) {
      const stored = all.find(x => x.id === ev.id);
      if (stored) ev = restorePhotos(ev, stored);
    }
    const isNew = !all.some(x => x.id === ev.id);
    ev.updated = new Date().toISOString();
    const i = all.findIndex(x => x.id === ev.id);
    if (i >= 0) all[i] = ev; else all.unshift(ev);
    bigSet(EVENTS_KEY, JSON.stringify(all));
    markDirty('ev_' + ev.id);
    scheduleSync();
    if (isNew && currentUser()) recordEvent('Event created: ' + (ev.name || 'Untitled') + (ev.orderNo ? ' (order ' + ev.orderNo + ')' : ''), currentUser().name);
  }
  function eventDelete(id) {
    if (!bigSettled) { whenReady(() => eventDelete(id)); return; }
    const existing = eventsAll().find(x => x.id === id);
    bigSet(EVENTS_KEY, JSON.stringify(eventsAll().filter(x => x.id !== id)));
    addTombstone('event', id);
    scheduleSync();
    if (existing && currentUser()) recordEvent('Event deleted: ' + (existing.name || 'Untitled'), currentUser().name);
  }

  /* ── One-time historical import (Jan-May 2026 orders, from a supplier
     summary PDF/spreadsheet — cost derived as after-discount minus profit
     where not given directly, discount % derived from budget vs after-
     discount; every month back-verified against the source's own month
     totals before being added here). Fixed ids make this safe to run more
     than once (same id just overwrites the same record). Name is a
     placeholder ("Order <no>") and date defaults to the 1st of the month
     where the source only gave a month, not a day (May had real per-order
     dates, so those are used as-is) — going forward, real events entered
     directly in-app will have both a real name and a real date. */
  const HIST_SEED_KEY = 'fl_seed_2026_jan_may';
  const HIST_EVENTS_2026 = [
    // January
    { orderNo: '239103', date: '2026-01-01', budget: 1295, discountPct: 19, cost: 370.00 },
    { orderNo: '238836', date: '2026-01-01', budget: 3800, discountPct: 10, cost: 1015.00 },
    { orderNo: '239496', date: '2026-01-01', budget: 32995, discountPct: 19, cost: 6185.00 },
    { orderNo: '239793', date: '2026-01-01', budget: 980, discountPct: 0, cost: 299.95 },
    { orderNo: '240943', date: '2026-01-01', budget: 1185, discountPct: 4.2194, cost: 376.20 },
    { orderNo: '241348', date: '2026-01-01', budget: 2175, discountPct: 0, cost: 450.00 },
    { orderNo: '241443', date: '2026-01-01', budget: 3500, discountPct: 19, cost: 1092.50 },
    { orderNo: '242876', date: '2026-01-01', budget: 5490, discountPct: 0, cost: 1380.00 },
    { orderNo: '243075', date: '2026-01-01', budget: 75000, discountPct: 20, cost: 14250.00 },
    { orderNo: '243435', date: '2026-01-01', budget: 790, discountPct: 10, cost: 241.30 },
    // February
    { orderNo: '244340', date: '2026-02-01', budget: 5545, discountPct: 0, cost: 1237.00 },
    { orderNo: '244641', date: '2026-02-01', budget: 790, discountPct: 15, cost: 241.30 },
    { orderNo: '244653', date: '2026-02-01', budget: 1200, discountPct: 10, cost: 282.00 },
    { orderNo: '247612', date: '2026-02-01', budget: 2400, discountPct: 15, cost: 768.00 },
    { orderNo: '244037', date: '2026-02-01', budget: 42605, discountPct: 10, cost: 12137.00 },
    { orderNo: '243965', date: '2026-02-01', budget: 52645, discountPct: 20, cost: 16979.90 },
    { orderNo: '245517', date: '2026-02-01', budget: 16020, discountPct: 10, cost: 6253.75 },
    { orderNo: '245303', date: '2026-02-01', budget: 22345, discountPct: 0, cost: 4124.50 },
    { orderNo: '246606', date: '2026-02-01', budget: 3345, discountPct: 10.0149, cost: 1260.00 },
    { orderNo: '246609', date: '2026-02-01', budget: 3300, discountPct: 0, cost: 598.00 },
    { orderNo: '246027', date: '2026-02-01', budget: 4895, discountPct: 0, cost: 2031.00 },
    { orderNo: '247302', date: '2026-02-01', budget: 8500, discountPct: 0, cost: 2798.40 },
    { orderNo: '247610', date: '2026-02-01', budget: 790, discountPct: 15, cost: 252.30 },
    { orderNo: '248613', date: '2026-02-01', budget: 700, discountPct: 0, cost: 251.00 },
    // March
    { orderNo: '250604', date: '2026-03-01', budget: 6885, discountPct: 19.971, cost: 1930.15 },
    { orderNo: '250837', date: '2026-03-01', budget: 23525, discountPct: 10, cost: 7864.50 },
    { orderNo: '250867', date: '2026-03-01', budget: 1995, discountPct: 19, cost: 729.00 },
    { orderNo: '251079', date: '2026-03-01', budget: 13995, discountPct: 10, cost: 4039.50 },
    { orderNo: '251491', date: '2026-03-01', budget: 43476.11, discountPct: 10, cost: 19302.75 },
    // April
    { orderNo: '252693', date: '2026-04-01', budget: 15000, discountPct: 0, cost: 3561.00 },
    { orderNo: '252928', date: '2026-04-01', budget: 88660, discountPct: 10, cost: 28302.00 },
    { orderNo: '253189', date: '2026-04-01', budget: 4125, discountPct: 20, cost: 1188.00 },
    { orderNo: '252838', date: '2026-04-01', budget: 3600, discountPct: 0, cost: 1005.00 },
    { orderNo: '253777', date: '2026-04-01', budget: 100000, discountPct: 0, cost: 38342.50 },
    { orderNo: '254374', date: '2026-04-01', budget: 4995, discountPct: 10, cost: 1739.50 },
    // May (real per-order dates given in the source)
    { orderNo: '255641', date: '2026-05-01', budget: 1620, discountPct: 20, cost: 670.50 },
    { orderNo: '255864', date: '2026-05-02', budget: 280, discountPct: 0, cost: 103.96 },
    { orderNo: '256725', date: '2026-05-09', budget: 9590, discountPct: 25, cost: 2602.00 },
    { orderNo: '257063', date: '2026-05-09', budget: 38780, discountPct: 0, cost: 10060.50 },
    { orderNo: '257448', date: '2026-05-12', budget: 1995, discountPct: 0, cost: 592.50 },
    { orderNo: '256727', date: '2026-05-13', budget: 55380, discountPct: 0, cost: 14619.50 },
    { orderNo: '257713', date: '2026-05-13', budget: 4600, discountPct: 19, cost: 930.50 },
    { orderNo: '257813', date: '2026-05-14', budget: 2595, discountPct: 19, cost: 739.00 },
    { orderNo: '257823', date: '2026-05-15', budget: 5995, discountPct: 20, cost: 1130.50 },
    { orderNo: '257971', date: '2026-05-17', budget: 1995, discountPct: 20, cost: 692.50 },
    { orderNo: '258685', date: '2026-05-20', budget: 890, discountPct: 20, cost: 308.00 },
    { orderNo: '258618', date: '2026-05-20', budget: 3395, discountPct: 0, cost: 871.50 },
    { orderNo: '258670', date: '2026-05-22', budget: 3250, discountPct: 20, cost: 1892.50 },
    { orderNo: '258687', date: '2026-05-23', budget: 1200, discountPct: 20, cost: 280.00 },
    { orderNo: '258560', date: '2026-05-24', budget: 1465, discountPct: 20, cost: 496.00 },
    { orderNo: '259311', date: '2026-05-25', budget: 13990, discountPct: 15, cost: 4897.00 },
    { orderNo: '259504', date: '2026-05-26', budget: 8575, discountPct: 0, cost: 1862.50 },
    { orderNo: '259394', date: '2026-05-26', budget: 11990, discountPct: 19, cost: 2973.50 }
  ];
  function seedHistoricalEvents() {
    if (localStorage.getItem(HIST_SEED_KEY)) return;
    HIST_EVENTS_2026.forEach(d => {
      eventSave({
        id: 'e_hist_' + d.orderNo,
        name: 'Order ' + d.orderNo,
        date: d.date,
        orderNo: d.orderNo,
        shopify: '',
        budget: d.budget,
        discountPct: d.discountPct,
        flowers: [],
        sundries: [],
        other: [{ name: 'Historical cost (imported)', qty: 1, price: d.cost }],
        notes: 'Imported from Jan-May 2026 historical summary',
        approval: { status: 'approved' }
      });
    });
    localStorage.setItem(HIST_SEED_KEY, '1');
  }

  /* ── Order tracker (manual entries when placing Shopify orders) ── */
  const TRACKER_KEY = 'fl_tracker';
  function trackerAll() { return JSON.parse(localStorage.getItem(TRACKER_KEY) || '[]'); }
  function trackerSave(row) {
    const all = trackerAll();
    const isNew = !all.some(x => x.id === row.id);
    row.updated = new Date().toISOString();
    const i = all.findIndex(x => x.id === row.id);
    if (i >= 0) all[i] = row; else all.unshift(row);
    localStorage.setItem(TRACKER_KEY, JSON.stringify(all));
    markDirty('trk_' + row.id);
    scheduleSync();
    if (isNew && currentUser()) recordEvent('Order added to tracker: ' + (row.orderNo || '—'), currentUser().name);
  }
  function trackerDelete(id) {
    const existing = trackerAll().find(x => x.id === id);
    localStorage.setItem(TRACKER_KEY, JSON.stringify(trackerAll().filter(x => x.id !== id)));
    addTombstone('tracker', id);
    scheduleSync();
    if (existing && currentUser()) recordEvent('Order removed from tracker: ' + (existing.orderNo || '—'), currentUser().name);
  }

  /* ── Client occasions (admin-only reminders — not tied to an order) ── */
  const OCCASIONS_KEY = 'fl_occasions';
  function occasionsAll() { return JSON.parse(localStorage.getItem(OCCASIONS_KEY) || '[]'); }
  function occasionSave(row) {
    const all = occasionsAll();
    const isNew = !all.some(x => x.id === row.id);
    row.updated = new Date().toISOString();
    const i = all.findIndex(x => x.id === row.id);
    if (i >= 0) all[i] = row; else all.unshift(row);
    localStorage.setItem(OCCASIONS_KEY, JSON.stringify(all));
    markDirty('occ_' + row.id);
    scheduleSync();
    if (isNew && currentUser()) recordEvent('Client occasion added: ' + (row.name || '—'), currentUser().name);
  }
  function occasionDelete(id) {
    const existing = occasionsAll().find(x => x.id === id);
    localStorage.setItem(OCCASIONS_KEY, JSON.stringify(occasionsAll().filter(x => x.id !== id)));
    addTombstone('occasion', id);
    scheduleSync();
    if (existing && currentUser()) recordEvent('Client occasion removed: ' + (existing.name || '—'), currentUser().name);
  }

  /* ── Event enquiries (sales pipeline — admin edits, CEO reviews) ── */

  /* Enquiry statuses. The app does ARITHMETIC with these: the CEO's pipeline
     figure and the home strip both ask "is this still live money?". So every
     status — including one Sajith invents — must declare which of three groups
     it belongs to, or a word like "client ghosted us" would be counted as live
     business for ever. Group is the only thing any calculation may look at;
     nothing anywhere should test the label itself. */
  const STATUS_GROUPS = ['open', 'won', 'lost'];
  const BUILT_IN_STATUSES = [
    { v: 'new',         l: 'New Enquiry',        g: 'open' },
    { v: 'contacted',   l: 'Contacted',          g: 'open' },
    { v: 'negotiating', l: 'Negotiating',        g: 'open' },
    { v: 'awaiting',    l: 'Awaiting Response',  g: 'open' },
    { v: 'confirmed',   l: 'Confirmed — Won',    g: 'won'  },
    { v: 'lost',        l: 'Lost / Declined',    g: 'lost' }
  ];
  /* custom ones live in the synced meta doc, so they reach every device */
  function customStatuses() {
    const list = metaDoc().statuses;
    return Array.isArray(list) ? list.filter(s => s && s.v && s.l && STATUS_GROUPS.indexOf(s.g) !== -1) : [];
  }
  function allStatuses() { return BUILT_IN_STATUSES.concat(customStatuses()); }
  function statusMetaOf(v) {
    const key = String(v || 'new').toLowerCase();
    return allStatuses().find(s => s.v === key) || BUILT_IN_STATUSES[0];
  }
  /* an UNKNOWN status counts as open — the safe default. Treating it as won or
     lost would quietly remove real money from the pipeline; treating it as open
     only means it stays visible until someone settles it. */
  function statusGroup(v) {
    const key = String(v || 'new').toLowerCase();
    const s = allStatuses().find(x => x.v === key);
    return s ? s.g : 'open';
  }
  /* "Paid" is a separate tick from the status word, and until Oct 2026 only the
     word was ever consulted — so an enquiry could be marked Paid and still be
     counted as live money everywhere. Three of Sajith's were, worth AED 39,970
     sitting in the CEO's pipeline as a maybe. Money in the bank wins over
     whatever the status still says; the word itself is left untouched, so
     unticking Paid puts everything back. */
  function enquiryWon(e) { return !!(e && (e.paid || statusGroup(e.status) === 'won')); }
  /* Jo's three buckets. Pending is simply "not decided yet" — Sajith's rule,
     and the simpler one: it does not matter whether an event date exists, it
     matters whether anyone has said won or lost. */
  function enquiryState(e) {
    if (enquiryWon(e)) return 'won';
    if (statusGroup(e && e.status) === 'lost') return 'lost';
    return 'pending';
  }

  /* ── Why an enquiry was lost ─────────────────────────────────────────
     Sajith already writes the reason in the notes — "No budget (500 AED)",
     "Choosed to take own florist". Rather than ask him to fill in a second
     field, this reads what he wrote and offers it back for him to confirm
     when he marks one Lost. Measured at 20 of 21 correct on his own data.
     The stored answer (`lostReason`) is what the chart counts; the guess is
     only ever a starting suggestion, never the final word. */
  const LOST_REASONS = ['Price / budget', 'No response', 'Client cancelled',
                        'Went elsewhere', 'Still deciding', 'Other'];
  /* first match wins, so the specific patterns come before the broad ones */
  const REASON_HINTS = [
    ['Went elsewhere',  /own florist|another florist|someone else|different (florist|supplier)/i],
    ['Client cancelled', /didn'?t proceed|did not proceed|cancell?ed|no longer need|doesn'?t need|does not need/i],
    ['No response',     /no respon|not respon|no reply|didn'?t reply|did not reply|ghost|went quiet/i],
    ['Price / budget',  /budget|afford|too high|price|no money|cheap|expensive|\bgp\b/i],
    ['Still deciding',  /still choos|still on chat|still think|waiting for (a )?(respond|response|additional)|contact me once/i]
  ];
  function guessLostReason(e) {
    const txt = ((e && e.messages || []).map(m => m && m.text || '').join(' · ') + ' ' + ((e && e.notes) || ''));
    if (!txt.trim()) return '';
    for (let i = 0; i < REASON_HINTS.length; i++) {
      if (REASON_HINTS[i][1].test(txt)) return REASON_HINTS[i][0];
    }
    return '';
  }
  /* what the chart counts: the confirmed answer, else the guess, else unknown */
  function lostReasonOf(e) {
    if (e && e.lostReason && LOST_REASONS.indexOf(e.lostReason) !== -1) return e.lostReason;
    return guessLostReason(e) || 'Not recorded';
  }
  function enquiryIsOpen(e) { return !(e && e.paid) && statusGroup(e && e.status) === 'open'; }
  function addCustomStatus(label, group) {
    const l = String(label || '').trim();
    if (!l || STATUS_GROUPS.indexOf(group) === -1) return null;
    const v = 'c_' + l.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
    if (v === 'c_' || allStatuses().some(s => s.v === v)) return null;
    const d = metaDoc();
    d.statuses = customStatuses().concat([{ v: v, l: l, g: group }]);
    d.updated = new Date().toISOString();
    localStorage.setItem(META_KEY, JSON.stringify(d));
    markDirty('meta_monthly');
    scheduleSync();
    if (currentUser()) recordEvent('Enquiry status added: ' + l + ' (' + group + ')', currentUser().name);
    return v;
  }
  /* built-ins are never removable — 'confirmed' and 'lost' are wired into the
     pipeline maths and the settle-before-folding rule on the enquiries page. */
  function removeCustomStatus(v) {
    if (BUILT_IN_STATUSES.some(s => s.v === v)) return false;
    const gone = customStatuses().find(s => s.v === v);
    const d = metaDoc();
    d.statuses = customStatuses().filter(s => s.v !== v);
    d.updated = new Date().toISOString();
    localStorage.setItem(META_KEY, JSON.stringify(d));
    markDirty('meta_monthly');
    scheduleSync();
    if (gone && currentUser()) recordEvent('Enquiry status removed: ' + gone.l, currentUser().name);
    return true;
  }
  /* how many enquiries still carry this word — asked before offering to remove it */
  function statusInUse(v) { return enquiriesAll().filter(e => String(e.status || '').toLowerCase() === v).length; }

  const ENQUIRIES_KEY = 'fl_enquiries';
  function enquiriesAll() { return JSON.parse(localStorage.getItem(ENQUIRIES_KEY) || '[]'); }
  function enquirySave(row) {
    const all = enquiriesAll();
    const isNew = !all.some(x => x.id === row.id);
    row.updated = new Date().toISOString();
    const i = all.findIndex(x => x.id === row.id);
    if (i >= 0) all[i] = row; else all.unshift(row);
    localStorage.setItem(ENQUIRIES_KEY, JSON.stringify(all));
    markDirty('enq_' + row.id);
    scheduleSync();
    if (isNew && currentUser()) recordEvent('Enquiry logged: ' + (row.name || '—'), currentUser().name);
  }
  function enquiryDelete(id) {
    const existing = enquiriesAll().find(x => x.id === id);
    localStorage.setItem(ENQUIRIES_KEY, JSON.stringify(enquiriesAll().filter(x => x.id !== id)));
    addTombstone('enquiry', id);
    scheduleSync();
    if (existing && currentUser()) recordEvent('Enquiry removed: ' + (existing.name || '—'), currentUser().name);
  }

  /* ── Event Calendar (admin-edit, ceo-comment) ────────────────
     Two shapes share this one collection, told apart by `type`:
       'chance'            — a manually-logged tentative date (id, date, text, comments[])
       'confirmed-comments' — just a comment thread hung off a real Tracker
                              order (id = 'conf_' + orderNo), since the order
                              itself already lives in the Tracker and isn't
                              duplicated here. */
  const CALENDAR_KEY = 'fl_calendar';
  function calendarAll() { return JSON.parse(localStorage.getItem(CALENDAR_KEY) || '[]'); }
  function calendarSave(row) {
    const all = calendarAll();
    row.updated = new Date().toISOString();
    const i = all.findIndex(x => x.id === row.id);
    if (i >= 0) all[i] = row; else all.push(row);
    localStorage.setItem(CALENDAR_KEY, JSON.stringify(all));
    markDirty('cal_' + row.id);
    scheduleSync();
  }
  function calendarDelete(id) {
    localStorage.setItem(CALENDAR_KEY, JSON.stringify(calendarAll().filter(x => x.id !== id)));
    addTombstone('calendar', id);
    scheduleSync();
  }
  function calendarAddComment(id, base, text) {
    const all = calendarAll();
    let row = all.find(x => x.id === id);
    if (!row) row = Object.assign({ id, comments: [] }, base);
    row.comments = row.comments || [];
    const u = currentUser();
    row.comments.push({ id: 'm' + Date.now(), name: u.name, role: role(u), text, ts: new Date().toISOString() });
    calendarSave(row);
  }

  /* ── Quotations (shared across devices, same pattern as events/tracker) ── */
  const QUOTES_KEY = 'fl_quotes';
  function quotesAll() { return JSON.parse(localStorage.getItem(QUOTES_KEY) || '[]'); }
  function quoteGet(id) { return quotesAll().find(x => x.id === id) || null; }
  function quoteSave(q) {
    const all = quotesAll();
    const isNew = !all.some(x => x.id === q.id);
    q.updated = new Date().toISOString();
    const i = all.findIndex(x => x.id === q.id);
    if (i >= 0) all[i] = q; else all.unshift(q);
    localStorage.setItem(QUOTES_KEY, JSON.stringify(all));
    markDirty('qt_' + q.id);
    scheduleSync();
    if (isNew && currentUser()) recordEvent('Quotation created: ' + (q.title || 'Untitled'), currentUser().name);
  }
  function quoteDelete(id) {
    const existing = quotesAll().find(x => x.id === id);
    localStorage.setItem(QUOTES_KEY, JSON.stringify(quotesAll().filter(x => x.id !== id)));
    addTombstone('quote', id);
    scheduleSync();
    if (existing && currentUser()) recordEvent('Quotation deleted: ' + (existing.title || 'Untitled'), currentUser().name);
  }

  /* ── Proposals (shared across devices, same pattern as events/tracker) ── */
  const PROPOSALS_KEY = 'fl_proposals';
  function proposalsAll() { return JSON.parse(localStorage.getItem(PROPOSALS_KEY) || '[]'); }
  function proposalGet(id) { return proposalsAll().find(x => x.id === id) || null; }
  function proposalSave(p) {
    const all = proposalsAll();
    const isNew = !all.some(x => x.id === p.id);
    p.updated = new Date().toISOString();
    const i = all.findIndex(x => x.id === p.id);
    if (i >= 0) all[i] = p; else all.unshift(p);
    localStorage.setItem(PROPOSALS_KEY, JSON.stringify(all));
    markDirty('pr_' + p.id);
    scheduleSync();
    if (isNew && currentUser()) recordEvent('Proposal created: ' + (p.title || 'Untitled'), currentUser().name);
  }
  function proposalDelete(id) {
    const existing = proposalsAll().find(x => x.id === id);
    localStorage.setItem(PROPOSALS_KEY, JSON.stringify(proposalsAll().filter(x => x.id !== id)));
    addTombstone('proposal', id);
    scheduleSync();
    if (existing && currentUser()) recordEvent('Proposal deleted: ' + (existing.title || 'Untitled'), currentUser().name);
  }

  /* ── Shared commission math (also duplicated in events.html/dashboard.html
     today — kept here too so the expense sheet doesn't need a 4th copy;
     worth centralizing the other two into this one eventually). ── */
  const COMMISSION_PCT = 10;
  function calcEventCommission(ev) {
    const sum = a => (a || []).reduce((s, l) => s + (parseFloat(l.qty) || 0) * (parseFloat(l.price) || 0), 0);
    const cost = sum(ev.flowers) + sum(ev.sundries) + sum(ev.other);
    const budget = parseFloat(ev.budget) || 0;
    const discount = budget * (parseFloat(ev.discountPct) || 0) / 100;
    const after = budget - discount;
    const profit = after - cost;
    return profit > 0 ? profit * COMMISSION_PCT / 100 : 0;
  }

  /* ── Expense sheets (monthly commission rollup) ──────────────────────
     An event's commission only becomes eligible once ITS OWN month's
     cutoff has passed (19th of the following month) — regardless of when
     it was actually approved. Approving a July event early in July must
     NOT make it appear before August 19. */
  function expenseCutoffDate(ym) {
    const [y, m] = ym.split('-').map(Number);
    const ny = m === 12 ? y + 1 : y;
    const nm = m === 12 ? 1 : m + 1;
    return new Date(ny, nm - 1, 19, 0, 0, 0);
  }
  function expenseCutoffPassed(ym) { return new Date() >= expenseCutoffDate(ym); }
  /* the feature only applies going forward from when Sajith actually started
     using it day-to-day — earlier months are historical import data with no
     real commission workflow behind them, so they're never offered. */
  const EXPENSE_FEATURE_START = '2026-06';
  function expenseLineItemsForMonth(ym) {
    if (ym < EXPENSE_FEATURE_START) return null;
    if (!expenseCutoffPassed(ym)) return null; // not open yet, regardless of approval status
    return eventsAll()
      .filter(e => e.date && e.date.slice(0, 7) === ym && e.approval && e.approval.status === 'approved')
      .map(e => ({ orderNo: e.orderNo || '', name: e.name || 'Untitled', commission: calcEventCommission(e) }))
      .filter(li => li.commission > 0);
  }
  /* CEO can only approve a month's sheet once every event dated that month
     has itself been through approval — a lingering pending/rejected event
     means the sheet's totals could still change, so approval stays blocked. */
  function expenseMonthFullyApproved(ym) {
    const evs = eventsAll().filter(e => e.date && e.date.slice(0, 7) === ym);
    if (!evs.length) return true;
    return evs.every(e => e.approval && e.approval.status === 'approved');
  }
  /* a sheet is a snapshot taken at generate time — if an event for that
     month gets approved afterwards, its commission never makes it in unless
     someone notices, so flag it rather than silently under-reporting. */
  function expenseSheetStale(exp) {
    const fresh = expenseLineItemsForMonth(exp.month) || [];
    const savedOrders = new Set((exp.lineItems || []).map(li => li.orderNo));
    return fresh.some(li => !savedOrders.has(li.orderNo));
  }
  /* runs from whichever team member's device happens to sync next — not just
     the admin's — so a month doesn't sit waiting on one specific person to
     open the app. Only ever creates a sheet once (existing-id check), and
     only reaches the network at all when a month has actually just become
     eligible, so this doesn't add meaningful sync traffic. */
  async function autoGenerateExpenseSheets() {
    try {
      const evs = eventsAll();
      const existing = expensesAll();
      const existingMonths = new Set(existing.map(x => x.month));
      const months = [...new Set(evs.filter(e => e.date).map(e => e.date.slice(0, 7)))];
      /* a month satisfying cutoff+approval stays true forever once it's
         first met — without excluding already-generated months here, this
         would re-fetch the team roster on every single sync, indefinitely,
         for a month that will never need generating again. */
      const eligible = months.filter(ym =>
        !existingMonths.has(ym) &&
        expenseCutoffPassed(ym) && expenseMonthFullyApproved(ym) && (expenseLineItemsForMonth(ym) || []).length);
      if (!eligible.length) return;
      const profiles = await fetchAllProfiles();
      const admin = profiles.find(p => p.role === 'admin' && !p.disabled);
      if (!admin) return;
      eligible.forEach(ym => {
        const id = 'exp_' + admin.id + '_' + ym;
        if (existing.some(x => x.id === id)) return;
        const items = expenseLineItemsForMonth(ym) || [];
        const total = items.reduce((s, i) => s + i.commission, 0);
        const sig = adminSignature();
        expenseSave({
          id, staffId: admin.id, staffName: admin.name, month: ym,
          lineItems: items, total,
          submittedAt: sig ? new Date().toISOString() : null, staffSignature: sig,
          ceoApproval: { approved: false, approvedAt: null, approvedByName: null },
          autoGenerated: true
        });
      });
    } catch (e) { /* not fatal — the next device with permission to list profiles will catch it */ }
  }
  const EXPENSES_KEY = 'fl_expenses';
  function expensesAll() { return JSON.parse(localStorage.getItem(EXPENSES_KEY) || '[]'); }
  function expenseGet(id) { return expensesAll().find(x => x.id === id) || null; }
  function expenseSave(x) {
    const all = expensesAll();
    const isNew = !all.some(y => y.id === x.id);
    x.updated = new Date().toISOString();
    const i = all.findIndex(y => y.id === x.id);
    if (i >= 0) all[i] = x; else all.unshift(x);
    localStorage.setItem(EXPENSES_KEY, JSON.stringify(all));
    markDirty('exp_' + x.id);
    scheduleSync();
    if (isNew && currentUser()) recordEvent('Expense sheet created: ' + (x.month || ''), currentUser().name);
  }
  function expenseDelete(id) {
    const existing = expensesAll().find(x => x.id === id);
    localStorage.setItem(EXPENSES_KEY, JSON.stringify(expensesAll().filter(x => x.id !== id)));
    addTombstone('expense', id);
    scheduleSync();
    if (existing && currentUser()) recordEvent('Expense sheet deleted: ' + (existing.month || ''), currentUser().name);
  }

  /* ── Admin's reusable signature (single synced doc, same idea as the
     monthly-override meta doc) — saved once when Admin signs a sheet by
     hand, then reused automatically on every sheet after that, including
     ones auto-generated on a device that isn't the admin's own. ── */
  const ADMIN_SIG_KEY = 'fl_admin_signature';
  function adminSignatureDoc() { return JSON.parse(localStorage.getItem(ADMIN_SIG_KEY) || '{}'); }
  function adminSignature() { return adminSignatureDoc().dataUrl || null; }
  /* The signature is copied WHOLE into every monthly expense sheet, so its size is
     multiplied by twelve a year. At 138 KB that was 1.6 MB/year into a ~5 MB box —
     which is what filled it in Aug 2026. Re-encoded small it is a rounding error,
     and at this width it still looks identical anywhere it is shown or printed. */
  const SIG_MAX_W = 420;

  /* The real cost of a signature PNG is not its width — it is the thousands of
     slightly-different half-transparent pixels along every stroke edge, which
     compress terribly. Snapping each pixel to either "clear" or "solid ink of one
     colour" took Sajith's own signature from 72 KB to 9.8 KB with no visible
     difference at printed size. The ink colour is measured from the image rather
     than forced to black, so a blue-pen signature stays blue. */
  const INK_CUTOFF = 60;          /* alpha below this is treated as nothing */
  function flattenInk(canvas) {
    try {
      const ctx = canvas.getContext('2d');
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const p = img.data;
      let r = 0, g = 0, b = 0, n = 0;
      for (let i = 0; i < p.length; i += 4) {
        if (p[i + 3] > 200) { r += p[i]; g += p[i + 1]; b += p[i + 2]; n++; }
      }
      if (n) { r = Math.round(r / n); g = Math.round(g / n); b = Math.round(b / n); }
      else { r = g = b = 0; }        /* nothing solid found — fall back to black */
      for (let i = 0; i < p.length; i += 4) {
        if (p[i + 3] < INK_CUTOFF) { p[i + 3] = 0; }
        else { p[i] = r; p[i + 1] = g; p[i + 2] = b; p[i + 3] = 255; }
      }
      ctx.putImageData(img, 0, 0);
    } catch (e) { /* tainted or unreadable canvas — leave it as drawn */ }
    return canvas;
  }

  function shrinkSignature(dataUrl) {
    return new Promise(resolve => {
      if (typeof document === 'undefined' || typeof Image === 'undefined' ||
          typeof dataUrl !== 'string' || dataUrl.slice(0, 5) !== 'data:') return resolve(dataUrl);
      const img = new Image();
      img.onload = () => {
        try {
          const w = img.naturalWidth || img.width, h = img.naturalHeight || img.height;
          if (!w || !h) return resolve(dataUrl);
          const scale = Math.min(1, SIG_MAX_W / w);
          const c = document.createElement('canvas');
          c.width = Math.max(1, Math.round(w * scale));
          c.height = Math.max(1, Math.round(h * scale));
          c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
          flattenInk(c);
          const out = c.toDataURL('image/png');
          /* never trade up — a tiny signature can re-encode larger */
          resolve(out && out.length < dataUrl.length ? out : dataUrl);
        } catch (e) { resolve(dataUrl); }
      };
      img.onerror = () => resolve(dataUrl);
      img.src = dataUrl;
    });
  }

  function setAdminSignature(dataUrl) {
    shrinkSignature(dataUrl).then(small => {
      const doc = { dataUrl: small, updated: new Date().toISOString() };
      localStorage.setItem(ADMIN_SIG_KEY, JSON.stringify(doc));
      markDirty('sig_admin');
      scheduleSync();
    });
  }

  /* One-off: shrink the signature already stored on this device, so sheets generated
     from today carry the small one. Existing sheets keep the copy they were signed
     with — June and July are CEO-approved financial records and are not touched. */
  const SIG_SHRUNK_KEY = 'fl_sig_shrunk_5_7_29';   /* bumped: 5.7.28 only resized, this pass also flattens the ink */
  function shrinkStoredSignature() {
    if (localStorage.getItem(SIG_SHRUNK_KEY)) return;
    const doc = adminSignatureDoc();
    if (!doc.dataUrl) return;                     /* nothing to do; retry once there is */
    shrinkSignature(doc.dataUrl).then(small => {
      localStorage.setItem(SIG_SHRUNK_KEY, '1');
      if (small === doc.dataUrl) return;          /* already small — leave it alone */
      localStorage.setItem(ADMIN_SIG_KEY, JSON.stringify(
        { dataUrl: small, updated: new Date().toISOString() }));
      markDirty('sig_admin');
      scheduleSync();
    }).catch(() => {});
  }

  /* ── Manual monthly-total overrides (admin sets the official number) ── */
  const META_KEY = 'fl_meta_monthly';
  function metaDoc() { return JSON.parse(localStorage.getItem(META_KEY) || '{"data":{}}'); }
  function monthlyOverrides() { return metaDoc().data || {}; }
  function setMonthlyOverride(ym, amount) {
    const d = metaDoc();
    d.data = d.data || {};
    const n = parseFloat(amount);
    if (amount === null || amount === '' || isNaN(n)) delete d.data[ym];
    else d.data[ym] = n;
    d.updated = new Date().toISOString();
    localStorage.setItem(META_KEY, JSON.stringify(d));
    markDirty('meta_monthly');
    recordEvent('Monthly total ' + (isNaN(n) ? 'cleared' : 'set to AED ' + n.toLocaleString()) + ' for ' + ym, currentUser().name);
    scheduleSync();
  }

  /* ── Company total trading income ─────────────────────────
     What the whole company billed in a month, taken from the finance system
     once the month closes and typed in here. Kept beside the monthly overrides
     in the same synced document.

     Deliberately NOT derived from anything in this app: it is the company's
     reported figure and must stay exactly what finance reported, so that the
     share calculated against it can be defended. A month with no figure simply
     has no share — the report never estimates one. */
  function companyIncome() { return metaDoc().company || {}; }
  function setCompanyIncome(ym, amount) {
    const d = metaDoc();
    d.company = d.company || {};
    const n = parseFloat(String(amount).replace(/,/g, ''));
    if (amount === null || amount === '' || isNaN(n)) delete d.company[ym];
    else d.company[ym] = n;
    d.updated = new Date().toISOString();
    localStorage.setItem(META_KEY, JSON.stringify(d));
    markDirty('meta_monthly');
    recordEvent('Company trading income ' + (isNaN(n) ? 'cleared' : 'set to AED ' + n.toLocaleString()) +
                ' for ' + ym, currentUser().name);
    scheduleSync();
  }

  /* Team-wide settings ride inside the meta document, which already syncs — this
     avoids inventing a whole new sync kind for two numbers. */
  /* Only the email preference is a setting. The GP target, the cut-off day and the
     commission rate are deliberately NOT settings: all three appear on, or decide, the
     documents Jo approves. Sajith's instruction — do not touch that area. */
  const SETTING_DEFAULTS = { emailMode: 'off' };
  function appSettings() {
    const s = (metaDoc().settings) || {};
    const out = {};
    Object.keys(SETTING_DEFAULTS).forEach(k => {
      out[k] = (s[k] === undefined || s[k] === null || s[k] === '') ? SETTING_DEFAULTS[k] : s[k];
    });
    return out;
  }
  function setAppSetting(key, value) {
    if (!(key in SETTING_DEFAULTS)) return;
    const d = metaDoc();
    d.settings = d.settings || {};
    d.settings[key] = value;
    d.updated = new Date().toISOString();
    localStorage.setItem(META_KEY, JSON.stringify(d));
    markDirty('meta_monthly');
    if (currentUser()) recordEvent('Setting changed: ' + key + ' = ' + value, currentUser().name);
    scheduleSync();
  }

  function appVersion() { return APP_VERSION; }

  /* ── "What's new", written per role ──────────────────────────────────
     An update used to land in silence: the CEO would simply find a button
     she had not asked for. Each release carries a short note per role,
     shown once on the first open after updating, then never again.
     A role with nothing to say shows NO card at all — an empty "nothing
     for you" box is worse than silence. */
  /* No APP_VERSION in here: this object is built as the file loads, and the
     const is declared further down — reading it here throws before the app
     has even started. The version is read inside the functions instead, which
     run long afterwards. (Same trap as SETTING_DEFAULTS, Sep 2026.) */
  const WHATS_NEW = {
    admin: [
      ['Invoices fill themselves in',
       'Upload a supplier invoice as a PDF on a GP sheet and the supplier name, the invoice number and the taxable total appear on the line. Check it and change anything you disagree with — it is only a starting point.'],
      ['The month in progress is no longer wrong',
       'The year table counted only the sheets you had written up, so the current month always looked far too small. It now counts the Tracker as well and marks the figure "so far" until the month closes.'],
      ['A report for the board',
       'On the Compare tab: what events sold against what the whole company billed, month by month, with a share for each. One year at a time, a button to compare with last year, and Download PDF.'],
      ['You enter the company figure',
       'Use Company totals on that report to type what the company billed each month, once the accounts close. One number a month.']
    ],
    ceo: [
      ['GP sheet lines name the supplier',
       'An invoice line now reads "Bloom House Flowers LLC — DS-26-17518" with the taxable amount beside it, instead of a file name. Easier to check what you are approving.'],
      ['How events compares with the whole company',
       'A new section on the Compare tab shows events sales as a share of everything the company billed, month by month, with last year beside it if you want it.']
    ],
    finance: [
      ['Events against company trading income',
       'A new section on the Compare tab sets events sales against company total trading income, month by month. Both figures include VAT, and only months where both are final show a share.']
    ]
  };
  const SEEN_VERSION_KEY = 'fl_last_version';
  /* Only someone who actually UPGRADED should see a changelog. A brand-new
     device has nothing to be told about, so it records the version quietly
     and shows nothing. Devices already carrying data but no recorded version
     (everyone, the first time this ships) count as upgraded. */
  function whatsNewFor(roleName) {
    const seen = localStorage.getItem(SEEN_VERSION_KEY);
    const upgraded = seen ? seen !== APP_VERSION : localStorage.getItem(EVENTS_KEY) !== null;
    if (!upgraded) { localStorage.setItem(SEEN_VERSION_KEY, APP_VERSION); return null; }
    const lines = WHATS_NEW[roleName] || [];
    if (!lines.length) { localStorage.setItem(SEEN_VERSION_KEY, APP_VERSION); return null; }
    return { version: APP_VERSION, lines: lines };
  }
  function markWhatsNewSeen() { localStorage.setItem(SEEN_VERSION_KEY, APP_VERSION); }
  /* Draws the card into an existing element and returns true if it drew one.
     Dismissing removes it and records the version, so it cannot come back. */
  function renderWhatsNew(elId) {
    const host = typeof document !== 'undefined' && document.getElementById(elId);
    if (!host) return false;
    const u = currentUser();
    if (!u) return false;
    const data = whatsNewFor(role(u));
    if (!data) return false;
    const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    host.innerHTML =
      '<div class="fl-nu">' +
        '<div class="fl-nu-hd"><h3>What&rsquo;s new</h3><span>Version ' + esc(data.version) + '</span></div>' +
        '<ul>' + data.lines.map(l =>
          '<li><span class="fl-nu-dot">&#10022;</span><span><b>' + esc(l[0]) + '</b><br>' + esc(l[1]) + '</span></li>'
        ).join('') + '</ul>' +
        '<div class="fl-nu-foot"><button type="button" id="fl-nu-ok">Got it</button>' +
        '<span>You will not see this again.</span></div>' +
      '</div>';
    if (!document.getElementById('fl-nu-style')) {
      const st = document.createElement('style');
      st.id = 'fl-nu-style';
      st.textContent =
        '.fl-nu{background:#fff;border:1px solid #E8DDD8;border-left:3px solid #E6CCA1;border-radius:3px;' +
          'padding:15px 17px;margin-bottom:16px;box-shadow:0 3px 20px rgba(85,3,24,.07);font-family:Lato,Arial,sans-serif;}' +
        '.fl-nu-hd{display:flex;align-items:baseline;gap:9px;}' +
        '.fl-nu-hd h3{font-family:"EB Garamond",Georgia,serif;font-size:16px;color:#550318;margin:0;font-weight:700;}' +
        '.fl-nu-hd span{font-size:9px;font-weight:800;letter-spacing:1.4px;text-transform:uppercase;color:#9B8E8A;}' +
        '.fl-nu ul{margin:9px 0 0;padding:0;list-style:none;}' +
        '.fl-nu li{display:flex;gap:9px;padding:7px 0;border-bottom:1px solid #E8DDD8;font-size:13px;color:#2E2522;line-height:1.5;}' +
        '.fl-nu li:last-child{border-bottom:none;}' +
        '.fl-nu-dot{color:#E6CCA1;font-size:14px;line-height:1.4;}' +
        '.fl-nu li b{color:#4B0D24;}' +
        '.fl-nu-foot{display:flex;align-items:center;gap:11px;margin-top:12px;flex-wrap:wrap;}' +
        '.fl-nu-foot button{background:linear-gradient(135deg,#3a0210,#550318);color:#E6CCA1;border:none;' +
          'border-radius:3px;padding:9px 18px;font-size:10px;font-weight:700;letter-spacing:1.5px;' +
          'text-transform:uppercase;cursor:pointer;font-family:inherit;min-height:36px;}' +
        '.fl-nu-foot span{font-size:10.5px;color:#9B8E8A;}';
      document.head.appendChild(st);
    }
    const ok = document.getElementById('fl-nu-ok');
    if (ok) ok.onclick = () => { markWhatsNewSeen(); host.innerHTML = ''; };
    return true;
  }

  /* ── Cloud sync (Supabase) — events + tracker shared across all devices ──
     Last-write-wins per record by `updated` timestamp; deletions travel as
     tombstones; offline changes push automatically when back online. */
  const SYNC = {
    url: 'https://nageqyossizmnzfwjxcf.supabase.co',
    key: 'sb_publishable_Kw0gYF5tCT_XnbloQcUzZQ_BL3PYT02'
  };

  /* Every network call goes through here. On mobile wifi a request can stall and
     never resolve OR reject — and syncNow only clears syncBusy after its try/catch,
     so one stalled call used to wedge the device on "SYNCING…" until the app was
     fully closed. An abort surfaces as a normal rejection, which the callers
     already handle, and the next cycle goes out 18 seconds later as usual. */
  const FETCH_MS = 30000;          /* the small checks — tiny payloads */
  const FETCH_UPLOAD_MS = 60000;   /* pushing work up; can be megabytes of photos */
  function fetchT(url, opts, ms) {
    if (typeof AbortController === 'undefined') return fetch(url, opts);
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), ms || FETCH_MS);
    return fetch(url, Object.assign({}, opts || {}, { signal: ctl.signal }))
      .then(r => { clearTimeout(timer); return r; },
            e => { clearTimeout(timer); throw e; });
  }
  const TOMB_KEY = 'fl_tombstones';
  const DIRTY_KEY = 'fl_dirty';        /* record ids with unpushed local changes */
  const SYNC_STAMP_KEY = 'fl_sync_stamp';   /* newest server `updated` we have seen */
  const FULL_SYNC_KEY = 'fl_last_full_sync';
  const LAST_HEARTBEAT_KEY = 'fl_last_heartbeat';

  /* one-time forced full resync for devices whose sync stamp advanced past
     kinds (enquiry, occasion, calendar) they didn't understand yet at the
     time — an incremental pull would otherwise skip that data forever,
     since it's now "older" than a stamp the device itself set while
     silently ignoring it. */
  const RESYNC_MARKER = 'fl_resync_5_7_25';
  if (!localStorage.getItem(RESYNC_MARKER)) {
    localStorage.removeItem(SYNC_STAMP_KEY);
    localStorage.removeItem(FULL_SYNC_KEY);
    localStorage.setItem(RESYNC_MARKER, '1');
  }

  function dirtySet() { return new Set(JSON.parse(localStorage.getItem(DIRTY_KEY) || '[]')); }
  function saveDirty(s) { localStorage.setItem(DIRTY_KEY, JSON.stringify([...s])); }
  const TOMB_KIND_OF = { ev_: 'event', trk_: 'tracker', qt_: 'quote', pr_: 'proposal',
                         exp_: 'expense', occ_: 'occasion', enq_: 'enquiry', cal_: 'calendar' };
  /* Saving a record means it exists again, so forget that it was ever deleted.
     Without this the 30-day tombstone would go on refusing a genuine re-creation —
     expense sheet ids are deterministic (exp_<staffId>_<month>), so that is real. */
  function clearTombstone(key) {
    const p = Object.keys(TOMB_KIND_OF).find(x => key.startsWith(x));
    if (!p) return;
    const kind = TOMB_KIND_OF[p], id = key.slice(p.length);
    const left = tombstones().filter(t => !(t.kind === kind && t.id === id));
    localStorage.setItem(TOMB_KEY, JSON.stringify(left));
  }
  function markDirty(key) { clearTombstone(key); const s = dirtySet(); s.add(key); saveDirty(s); }

  let syncBusy = false;
  let syncTimer = null;
  const syncListeners = [];
  function onSync(fn) { syncListeners.push(fn); }
  function emitSync(state) { syncListeners.forEach(f => { try { f(state); } catch (e) {} }); }

  function syncEnabled() { return !!(SYNC.url && SYNC.key); }
  async function syncHeaders() {
    const token = await ensureFreshToken();
    return { apikey: SYNC.key, Authorization: 'Bearer ' + (token || SYNC.key), 'Content-Type': 'application/json' };
  }
  /* ── Blind-spot safety net (both directions) ─────────────────
     `updated` is stamped when a row is SAVED ON THE DEVICE, but the row
     only reaches the server when that device next pushes. If a device is
     asleep, offline or backgrounded for hours, its rows arrive already
     "older" than the cursor other devices have since moved past — so the
     incremental pull never asks for them and they stay invisible until the
     next full pull. That really happened: six tracker orders entered on the
     tablet one evening were still missing on the PC the next morning
     (2026-09-01). Clock differences between devices widen the same gap.

     Fix: every couple of minutes pull a MANIFEST — id/kind/updated only, no
     `data`, so no invoice photos and it stays a few KB — and compare it
     against what is actually on disk, row by row:
       · server has something newer, or we lack it   → fetch it by id
       · we have something the server lacks or is older → re-queue our push
     Comparing rows directly instead of trusting a global time cursor means
     neither a late upload nor a wrong clock can hide anything, in either
     direction. `log` is excluded: the local copy is capped at 500 entries,
     so trimmed-away rows would look "missing" forever. */
  const RECONCILE_KEY = 'fl_last_reconcile';
  /* The manifest is ~95 bytes/row, so a few hundred rows is ~20KB. Running it
     on every 18s sync would cost ~5GB/month across the team — wasteful, since
     the ordinary incremental pull already handles the normal case in ~18s and
     this is only the backstop. So: every 2 minutes, only while the app is
     actually on screen, plus an immediate check the moment it comes back into
     view — which is exactly when a device is most likely to be behind (laptop
     opened in the morning after the tablet was used overnight). Works out
     under ~1GB/month. */
  const RECONCILE_EVERY_MS = 2 * 60 * 1000;
  let reconcileASAP = true;          /* first sync after launch always checks */
  const ID_PREFIX = { event: 'ev_', tracker: 'trk_', quote: 'qt_', proposal: 'pr_',
                      expense: 'exp_', occasion: 'occ_', enquiry: 'enq_', calendar: 'cal_' };

  /* id (as stored server-side) → local `updated`, for every row we hold */
  function localRowIndex() {
    const idx = new Map();
    const add = (prefix, rows) => rows.forEach(r => idx.set(prefix + r.id, r.updated || ''));
    add(ID_PREFIX.event, eventsAll());
    add(ID_PREFIX.tracker, trackerAll());
    add(ID_PREFIX.quote, quotesAll());
    add(ID_PREFIX.proposal, proposalsAll());
    add(ID_PREFIX.expense, expensesAll());
    add(ID_PREFIX.occasion, occasionsAll());
    add(ID_PREFIX.enquiry, enquiriesAll());
    add(ID_PREFIX.calendar, calendarAll());
    const m = metaDoc();   if (m.updated) idx.set('meta_monthly', m.updated);
    const s = adminSignatureDoc(); if (s.updated) idx.set('sig_admin', s.updated);
    return idx;
  }

  /* returns full rows the incremental pull missed (empty array if none/not due) */
  async function reconcileMissingRows(headers, alreadyPulled, force) {
    try {
      const last = parseInt(localStorage.getItem(RECONCILE_KEY) || '0');
      const hidden = typeof document !== 'undefined' && document.hidden;
      const due = force || reconcileASAP || (!hidden && Date.now() - last >= RECONCILE_EVERY_MS);
      if (!due) return [];
      reconcileASAP = false;
      const res = await fetchT(SYNC.url + '/rest/v1/fl_shared?select=id,kind,updated,deleted&kind=neq.log', { headers });
      if (!res.ok) return [];
      const manifest = await res.json();
      localStorage.setItem(RECONCILE_KEY, String(Date.now()));

      const local = localRowIndex();
      const pulled = new Set(alreadyPulled.map(r => r.id));
      const tombKeys = new Set(tombstones().map(t => t.kind + ':' + t.id));
      const bareOf = id => id.replace(/^(ev_|trk_|qt_|pr_|exp_|occ_|enq_|cal_)/, '');

      /* Compare timestamps as MOMENTS, never as text. The two sides spell the
         same instant differently — this device writes "…589Z", Postgres hands
         back "…589+00:00" — and as text "Z" sorts after "+", so every record
         looked newer here than on the server. That marked everything for
         re-upload on every pass: the whole events blob, photos and all, every
         couple of minutes, forever. It is why syncing felt slow. Sep 2026. */
      const tval = v => { const n = Date.parse(v || ''); return isNaN(n) ? 0 : n; };

      /* ── download side ── */
      const onServer = new Map();
      const need = manifest.filter(m => {
        onServer.set(m.id, m.deleted ? null : (m.updated || ''));
        if (pulled.has(m.id)) return false;              /* this sync already has it */
        const mine = local.get(m.id);
        if (m.deleted) return mine !== undefined;        /* only if we still hold it */
        if (mine === undefined) {
          /* don't resurrect something this device just deleted — its own
             tombstone is still queued and will win on the next push */
          return !tombKeys.has(m.kind + ':' + bareOf(m.id));
        }
        return tval(m.updated) > tval(mine);
      }).map(m => m.id);

      /* ── upload side: our row never made it up, or landed as an older copy.
         localRowIndex() is keyed by the same prefixed id the push loop uses
         as its dirty key, so re-queueing is just markDirty(id). ── */
      local.forEach((mine, id) => {
        if (!onServer.has(id)) { markDirty(id); return; }   /* server never got it */
        const theirs = onServer.get(id);
        if (theirs === null) return;                        /* deleted upstream — let the merge remove it */
        if (tval(mine) > tval(theirs)) markDirty(id);       /* ours is genuinely newer */
      });

      if (!need.length) return [];

      /* fetch in chunks so the URL can't grow unbounded */
      const out = [];
      for (let i = 0; i < need.length; i += 40) {
        const ids = need.slice(i, i + 40).map(id => '"' + id + '"').join(',');
        const r2 = await fetchT(SYNC.url + '/rest/v1/fl_shared?select=id,kind,data,deleted,updated&id=in.(' + encodeURIComponent(ids) + ')', { headers });
        if (r2.ok) out.push(...await r2.json());
      }
      return out;
    } catch (e) { return []; }   /* never let the safety net break the real sync */
  }

  /* how long a pushed tombstone is remembered — long enough that a device left off
     for weeks cannot bring a deleted record back when it finally wakes up */
  const TOMB_KEEP_MS = 30 * 24 * 3600 * 1000;
  function tombstones() { return JSON.parse(localStorage.getItem(TOMB_KEY) || '[]'); }
  function addTombstone(kind, id) {
    const t = tombstones();
    t.push({ id, kind, at: new Date().toISOString() });
    localStorage.setItem(TOMB_KEY, JSON.stringify(t));
  }

  function scheduleSync() {
    if (!syncEnabled()) return;
    clearTimeout(syncTimer);
    syncTimer = setTimeout(syncNow, 1500);
  }

  async function syncNow() {
    /* requires a real logged-in session now — fl_shared no longer accepts
       anonymous access. INCREMENTAL: pulls only rows changed since the last
       sync (a full pull happens on first run and once a day as a safety
       net) — keeps data usage tiny instead of re-downloading every invoice photo. */
    if (!syncEnabled() || syncBusy || !currentUser()) return;
    /* syncing before the store has loaded would compare the cloud against an
       empty local list and push deletions/blanks. Wait one cycle. */
    if (!bigSettled) return;
    if (!navigator.onLine) { emitSync('offline'); return; }
    syncBusy = true;
    emitSync('syncing');
    try {
      const headers = await syncHeaders();
      const lastStamp = localStorage.getItem(SYNC_STAMP_KEY) || '';
      const lastFull = parseInt(localStorage.getItem(FULL_SYNC_KEY) || '0');
      const fullPull = !lastStamp || (Date.now() - lastFull > 24 * 3600 * 1000);
      let pullUrl = SYNC.url + '/rest/v1/fl_shared?select=id,kind,data,deleted,updated';
      if (!fullPull) {
        /* 2-minute overlap absorbs clock differences; re-merging is harmless */
        const from = new Date(new Date(lastStamp).getTime() - 120000).toISOString();
        pullUrl += '&updated=gte.' + encodeURIComponent(from);
      }
      const res = await fetchT(pullUrl, { headers });
      if (!res.ok) throw new Error('pull ' + res.status);
      let remote = await res.json();

      /* catch anything the cursor skipped (see reconcileMissingRows) — the
         rows come back in the same shape, so the merge below handles them
         with no special-casing. Skipped right after a full pull: that just
         read everything already. */
      if (!fullPull) {
        const recovered = await reconcileMissingRows(headers, remote);
        if (recovered.length) remote = remote.concat(recovered);
      }

      let maxStamp = lastStamp;
      remote.forEach(r => { if (r.updated > maxStamp) maxStamp = r.updated; });

      const tombs = tombstones();
      const tombKeys = new Set(tombs.map(t => t.kind + ':' + t.id));
      /* only the ones the cloud hasn't been told about yet get pushed; the rest are
         kept (see TOMB_KEEP_MS) purely so tombKeys can keep refusing the record */
      const unsentTombs = tombs.filter(t => !t.sent);
      const dirty = dirtySet();
      const dirtySnapshot = new Set(dirty);

      /* merge remote → local; when the cloud wins, drop the local dirty flag */
      let evs = eventsAll();
      let trk = trackerAll();
      let qts = quotesAll();
      let props = proposalsAll();
      let exps = expensesAll();
      let occs = occasionsAll();
      let enqs = enquiriesAll();
      let cal = calendarAll();
      let meta = metaDoc();
      let sig = adminSignatureDoc();
      let log = activityLog();
      const logIds = new Set(log.map(e => e.id));
      remote.forEach(r => {
        const bare = r.id.replace(/^(ev_|trk_|qt_|pr_|exp_|occ_|enq_|cal_)/, '');
        if (r.kind === 'log' && !r.deleted) {
          /* append-only audit trail: every device's actions merge into one shared log */
          if (!logIds.has(r.id)) { log.push(r.data); logIds.add(r.id); }
        } else if (r.kind === 'meta' && r.id === 'meta_monthly' && !r.deleted) {
          if ((r.data.updated || '') > (meta.updated || '')) { meta = r.data; dirty.delete('meta_monthly'); }
        } else if (r.kind === 'signature' && r.id === 'sig_admin' && !r.deleted) {
          if ((r.data.updated || '') > (sig.updated || '')) { sig = r.data; dirty.delete('sig_admin'); }
        } else if (r.kind === 'event') {
          const local = evs.find(e => e.id === bare);
          if (r.deleted) {
            if (local) evs = evs.filter(e => e.id !== bare);
            /* a delete always wins, and the dirty flag goes whether or not we held a
               copy — otherwise this device pushes its stale row back and resurrects it */
            dirty.delete(r.id);
          } else if (!tombKeys.has('event:' + bare)) {
            if (!local) evs.unshift(r.data);
            else if ((r.data.updated || '') > (local.updated || '')) { evs = evs.map(e => e.id === bare ? r.data : e); dirty.delete(r.id); }
          }
        } else if (r.kind === 'tracker') {
          const local = trk.find(x => x.id === bare);
          if (r.deleted) {
            if (local) trk = trk.filter(x => x.id !== bare);
            /* a delete always wins, and the dirty flag goes whether or not we held a
               copy — otherwise this device pushes its stale row back and resurrects it */
            dirty.delete(r.id);
          } else if (!tombKeys.has('tracker:' + bare)) {
            if (!local) trk.unshift(r.data);
            else if ((r.data.updated || '') > (local.updated || '')) { trk = trk.map(x => x.id === bare ? r.data : x); dirty.delete(r.id); }
          }
        } else if (r.kind === 'quote') {
          const local = qts.find(x => x.id === bare);
          if (r.deleted) {
            if (local) qts = qts.filter(x => x.id !== bare);
            /* a delete always wins, and the dirty flag goes whether or not we held a
               copy — otherwise this device pushes its stale row back and resurrects it */
            dirty.delete(r.id);
          } else if (!tombKeys.has('quote:' + bare)) {
            if (!local) qts.unshift(r.data);
            else if ((r.data.updated || '') > (local.updated || '')) { qts = qts.map(x => x.id === bare ? r.data : x); dirty.delete(r.id); }
          }
        } else if (r.kind === 'proposal') {
          const local = props.find(x => x.id === bare);
          if (r.deleted) {
            if (local) props = props.filter(x => x.id !== bare);
            /* a delete always wins, and the dirty flag goes whether or not we held a
               copy — otherwise this device pushes its stale row back and resurrects it */
            dirty.delete(r.id);
          } else if (!tombKeys.has('proposal:' + bare)) {
            if (!local) props.unshift(r.data);
            else if ((r.data.updated || '') > (local.updated || '')) { props = props.map(x => x.id === bare ? r.data : x); dirty.delete(r.id); }
          }
        } else if (r.kind === 'expense') {
          const local = exps.find(x => x.id === bare);
          if (r.deleted) {
            if (local) exps = exps.filter(x => x.id !== bare);
            /* a delete always wins, and the dirty flag goes whether or not we held a
               copy — otherwise this device pushes its stale row back and resurrects it */
            dirty.delete(r.id);
          } else if (!tombKeys.has('expense:' + bare)) {
            if (!local) exps.unshift(r.data);
            else if ((r.data.updated || '') > (local.updated || '')) { exps = exps.map(x => x.id === bare ? r.data : x); dirty.delete(r.id); }
          }
        } else if (r.kind === 'occasion') {
          const local = occs.find(x => x.id === bare);
          if (r.deleted) {
            if (local) occs = occs.filter(x => x.id !== bare);
            /* a delete always wins, and the dirty flag goes whether or not we held a
               copy — otherwise this device pushes its stale row back and resurrects it */
            dirty.delete(r.id);
          } else if (!tombKeys.has('occasion:' + bare)) {
            if (!local) occs.unshift(r.data);
            else if ((r.data.updated || '') > (local.updated || '')) { occs = occs.map(x => x.id === bare ? r.data : x); dirty.delete(r.id); }
          }
        } else if (r.kind === 'enquiry') {
          const local = enqs.find(x => x.id === bare);
          if (r.deleted) {
            if (local) enqs = enqs.filter(x => x.id !== bare);
            /* a delete always wins, and the dirty flag goes whether or not we held a
               copy — otherwise this device pushes its stale row back and resurrects it */
            dirty.delete(r.id);
          } else if (!tombKeys.has('enquiry:' + bare)) {
            if (!local) enqs.unshift(r.data);
            else if ((r.data.updated || '') > (local.updated || '')) { enqs = enqs.map(x => x.id === bare ? r.data : x); dirty.delete(r.id); }
          }
        } else if (r.kind === 'calendar') {
          const local = cal.find(x => x.id === bare);
          if (r.deleted) {
            if (local) cal = cal.filter(x => x.id !== bare);
            /* a delete always wins, and the dirty flag goes whether or not we held a
               copy — otherwise this device pushes its stale row back and resurrects it */
            dirty.delete(r.id);
          } else if (!tombKeys.has('calendar:' + bare)) {
            if (!local) cal.push(r.data);
            else if ((r.data.updated || '') > (local.updated || '')) { cal = cal.map(x => x.id === bare ? r.data : x); dirty.delete(r.id); }
          }
        }
      });
      /* Saving what we just downloaded must never abort the sync before the
         UPLOAD below. If this device is out of room, its own unsent work is
         the one thing that exists nowhere else — losing the chance to push it
         is far worse than failing to cache someone else's changes. Before
         Sep 2026 a single failure here threw, skipped the upload entirely,
         and stranded a day's work on the tablet. */
      const save = (k, v) => { try { localStorage.setItem(k, v); } catch (e) { reportStorageProblem(e); } };
      try { bigSet(EVENTS_KEY, JSON.stringify(evs)); } catch (e) { /* already reported */ }
      save(TRACKER_KEY, JSON.stringify(trk));
      save(QUOTES_KEY, JSON.stringify(qts));
      save(PROPOSALS_KEY, JSON.stringify(props));
      save(EXPENSES_KEY, JSON.stringify(exps));
      save(OCCASIONS_KEY, JSON.stringify(occs));
      save(ENQUIRIES_KEY, JSON.stringify(enqs));
      save(CALENDAR_KEY, JSON.stringify(cal));
      if (meta.updated) save(META_KEY, JSON.stringify(meta));
      if (sig.updated) save(ADMIN_SIG_KEY, JSON.stringify(sig));
      log.sort((a, b) => (b.time || '').localeCompare(a.time || ''));
      save(LOG_KEY, JSON.stringify(log.slice(0, 500)));
      saveDirty(dirty);

      /* push ONLY records with local changes + pending deletions */
      const batch = [];
      dirty.forEach(key => {
        if (key.startsWith('ev_')) {
          const e = evs.find(x => 'ev_' + x.id === key);
          if (e) batch.push({ id: key, kind: 'event', data: e, deleted: false, updated: e.updated || new Date().toISOString() });
        } else if (key.startsWith('trk_')) {
          const x = trk.find(t => 'trk_' + t.id === key);
          if (x) batch.push({ id: key, kind: 'tracker', data: x, deleted: false, updated: x.updated || new Date().toISOString() });
        } else if (key.startsWith('qt_')) {
          const q = qts.find(t => 'qt_' + t.id === key);
          if (q) batch.push({ id: key, kind: 'quote', data: q, deleted: false, updated: q.updated || new Date().toISOString() });
        } else if (key.startsWith('pr_')) {
          const p = props.find(t => 'pr_' + t.id === key);
          if (p) batch.push({ id: key, kind: 'proposal', data: p, deleted: false, updated: p.updated || new Date().toISOString() });
        } else if (key.startsWith('exp_')) {
          const x = exps.find(t => 'exp_' + t.id === key);
          if (x) batch.push({ id: key, kind: 'expense', data: x, deleted: false, updated: x.updated || new Date().toISOString() });
        } else if (key.startsWith('occ_')) {
          const x = occs.find(t => 'occ_' + t.id === key);
          if (x) batch.push({ id: key, kind: 'occasion', data: x, deleted: false, updated: x.updated || new Date().toISOString() });
        } else if (key.startsWith('enq_')) {
          const x = enqs.find(t => 'enq_' + t.id === key);
          if (x) batch.push({ id: key, kind: 'enquiry', data: x, deleted: false, updated: x.updated || new Date().toISOString() });
        } else if (key.startsWith('cal_')) {
          const x = cal.find(t => 'cal_' + t.id === key);
          if (x) batch.push({ id: key, kind: 'calendar', data: x, deleted: false, updated: x.updated || new Date().toISOString() });
        } else if (key === 'meta_monthly') {
          const m = metaDoc();
          if (m.updated) batch.push({ id: 'meta_monthly', kind: 'meta', data: m, deleted: false, updated: m.updated });
        } else if (key === 'sig_admin') {
          const s = adminSignatureDoc();
          if (s.updated) batch.push({ id: 'sig_admin', kind: 'signature', data: s, deleted: false, updated: s.updated });
        } else if (key.startsWith('log_')) {
          const entry = log.find(e => e.id === key);
          if (entry) batch.push({ id: key, kind: 'log', data: entry, deleted: false, updated: entry.time });
        }
      });
      unsentTombs.forEach(t => {
        const prefix = t.kind === 'event' ? 'ev_' : t.kind === 'tracker' ? 'trk_' : t.kind === 'quote' ? 'qt_' : t.kind === 'proposal' ? 'pr_' : t.kind === 'occasion' ? 'occ_' : t.kind === 'enquiry' ? 'enq_' : t.kind === 'calendar' ? 'cal_' : 'exp_';
        batch.push({ id: prefix + t.id, kind: t.kind, data: { id: t.id, updated: t.at }, deleted: true, updated: t.at });
      });
      /* a deleted-then-recreated record (expense sheet ids are deterministic —
         exp_<staffId>_<month> — so this happens for real) can put the same id
         in this batch twice: once from its tombstone, once from its new dirty
         save. Postgres's ON CONFLICT rejects the whole request if the same id
         appears more than once in one upsert, so dedupe first — last-write-wins
         by `updated`, same rule used everywhere else in this sync engine. */
      const byId = new Map();
      batch.forEach(item => {
        const existing = byId.get(item.id);
        if (!existing || (item.updated || '') > (existing.updated || '')) byId.set(item.id, item);
      });
      const dedupedBatch = [...byId.values()];
      if (dedupedBatch.length) {
        const res2 = await fetchT(SYNC.url + '/rest/v1/fl_shared?on_conflict=id', {
          method: 'POST',
          headers: Object.assign(headers, { Prefer: 'resolution=merge-duplicates,return=minimal' }),
          body: JSON.stringify(dedupedBatch)
        }, FETCH_UPLOAD_MS);
        if (!res2.ok) throw new Error('push ' + res2.status);
      }

      /* clear only what we actually pushed — changes made mid-sync stay queued */
      const after = dirtySet();
      dirtySnapshot.forEach(k => after.delete(k));
      saveDirty(after);
      /* A tombstone used to be thrown away the moment it was pushed. That left nothing
         to stop a device which had been offline since before the delete from pushing
         its stale copy back up — the upsert overwrites without comparing timestamps,
         so the record came back from the dead. Mark them sent instead and keep them
         for TOMB_KEEP_MS, which is what tombKeys needs to go on refusing the row. */
      const sentKeys = new Set(unsentTombs.map(t => t.kind + ':' + t.id + ':' + t.at));
      const cutoff = Date.now() - TOMB_KEEP_MS;
      const remainingTombs = tombstones()
        .map(t => sentKeys.has(t.kind + ':' + t.id + ':' + t.at) ? Object.assign({}, t, { sent: true }) : t)
        .filter(t => { const at = Date.parse(t.at || ''); return !t.sent || isNaN(at) || at >= cutoff; });
      localStorage.setItem(TOMB_KEY, JSON.stringify(remainingTombs));

      /* An empty cloud used to leave maxStamp as '' — the cursor was then never
         written, so every sync from then on was a full "send me everything" pull. */
      localStorage.setItem(SYNC_STAMP_KEY, maxStamp || new Date().toISOString());
      if (fullPull) localStorage.setItem(FULL_SYNC_KEY, String(Date.now()));
      pushDeviceHeartbeat(headers).catch(() => {});
      await autoGenerateExpenseSheets();
      emitSync('synced');
    } catch (e) {
      emitSync('offline');
    }
    syncBusy = false;
  }

  /* Open the store FIRST, and unconditionally — pages now wait on it, so if
     this never ran (sync disabled, or an early return) they would wait for
     ever. It must settle on every path. */
  initBigStore();

  /* keep devices fresh: team is always online — sync fast and often */
  if (syncEnabled()) {
    if (currentUser()) { seedHistoricalEvents(); shrinkStoredSignature(); }
    setTimeout(syncNow, 1500);
    setInterval(syncNow, 18000);
    /* coming back online, or back on screen, is exactly when this device is
       most likely to be behind — cross-check immediately, don't wait 2 min */
    window.addEventListener('online', () => { reconcileASAP = true; syncNow(); });
    document.addEventListener('visibilitychange', () => { if (!document.hidden) { reconcileASAP = true; syncNow(); } });
  }

  /* ── Auto-update ────────────────────────────────────────────
     New releases are published to Supabase storage. Phones get a
     tap-to-update banner; the Windows app downloads silently via
     electron-updater and the banner restarts it. */
  const APP_VERSION = '5.7.37';
  const UPDATE_BASE = SYNC.url + '/storage/v1/object/public/updates';
  const IS_ELECTRON = /electron/i.test(navigator.userAgent);

  function verCmp(a, b) {
    const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number);
    for (let i = 0; i < 3; i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
    return 0;
  }

  function showUpdateBanner(info) {
    if (document.getElementById('fl-update-banner')) return;
    if (sessionStorage.getItem('fl_update_dismissed') === info.version) return;
    const el = document.createElement('div');
    el.id = 'fl-update-banner';
    el.innerHTML =
      '<div style="position:fixed;top:0;left:0;right:0;z-index:9999;background:linear-gradient(135deg,#F3E3C3,#E6CCA1);padding:12px 14px;display:flex;align-items:center;gap:12px;box-shadow:0 6px 24px rgba(75,13,36,.35);font-family:Lato,Arial,sans-serif;">' +
      '<span style="font-size:19px;">⬆</span>' +
      '<span style="flex:1;min-width:0;"><b style="color:#4B0D24;font-size:13px;">New version available — ' + info.version + '</b><br>' +
      '<span style="color:#7a5c33;font-size:11px;">' + (info.electron ? 'Downloaded and ready — restarts the app' : (info.notes || 'Improvements & fixes')) + '</span></span>' +
      '<button id="fl-update-go" style="background:#4B0D24;color:#E6CCA1;border:none;padding:10px 16px;border-radius:3px;font-size:11px;font-weight:700;letter-spacing:1.5px;cursor:pointer;font-family:inherit;">UPDATE NOW</button>' +
      '<button id="fl-update-x" style="background:none;border:none;color:#7a5c33;font-size:16px;cursor:pointer;padding:6px;">✕</button></div>';
    document.body.appendChild(el);
    document.getElementById('fl-update-go').onclick = () => {
      if (info.electron && window.flUpdate) window.flUpdate.install();
      else if (info.apkUrl) {
        const a = document.createElement('a');
        a.href = info.apkUrl; a.target = '_blank'; a.rel = 'noopener';
        document.body.appendChild(a); a.click(); a.remove();
      }
    };
    document.getElementById('fl-update-x').onclick = () => {
      sessionStorage.setItem('fl_update_dismissed', info.version);
      el.remove();
    };
  }

  async function checkForUpdate() {
    if (IS_ELECTRON) return;                      /* desktop handled natively below */
    if (!syncEnabled() || !navigator.onLine) return;
    try {
      const res = await fetchT(UPDATE_BASE + '/latest.json?t=' + Math.floor(Date.now() / 60000), { cache: 'no-store' });
      if (!res.ok) return;
      const info = await res.json();
      if (info && info.version && verCmp(info.version, APP_VERSION) > 0) showUpdateBanner(info);
    } catch (e) {}
  }

  function initUpdates() {
    if (IS_ELECTRON && window.flUpdate) {
      /* electron-updater already downloaded it in the background */
      window.flUpdate.onReady(version => showUpdateBanner({ version, electron: true }));
    } else {
      setTimeout(checkForUpdate, 3000);
      setInterval(checkForUpdate, 10 * 1000);
      document.addEventListener('visibilitychange', () => { if (!document.hidden) checkForUpdate(); });
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initUpdates);
  else initUpdates();

  /* ── Activity log + email alerts ─────────────────────────── */
  function deviceLabel() {
    let d = localStorage.getItem('fl_device_id');
    if (!d) {
      d = 'device-' + Math.random().toString(36).slice(2, 8);
      localStorage.setItem('fl_device_id', d);
    }
    return d;
  }
  /* the row id this device writes its heartbeat under. Two machines can share a
     NAME, so anything asking "is this me?" must compare on this, not the name. */
  function deviceId() { return 'device_' + deviceLabel(); }

  /* a friendly name for THIS device only — set locally, never synced */
  function deviceName() { return localStorage.getItem('fl_device_name') || deviceLabel(); }
  function setDeviceName(name) {
    name = (name || '').trim();
    if (name) localStorage.setItem('fl_device_name', name);
    else localStorage.removeItem('fl_device_name');
  }

  /* one small "this device is alive, and here's who's using it" record per
     device, updated at most every 10 minutes (not every 15s sync) so it
     doesn't spam the database — lets the admin panel show every device and
     when it last synced, regardless of whether anyone's actively logging in. */
  async function pushDeviceHeartbeat(headers) {
    const last = parseInt(localStorage.getItem(LAST_HEARTBEAT_KEY) || '0');
    if (Date.now() - last < 10 * 60000) return;
    const me = currentUser();
    const payload = {
      id: 'device_' + deviceLabel(),
      kind: 'device',
      /* version travels with the heartbeat so the Admin panel can show which
         devices are behind — the tablet sat three weeks stale and nothing said so */
      data: { device: deviceName(), who: me ? me.name : null, time: new Date().toISOString(),
              version: APP_VERSION },
      deleted: false,
      updated: new Date().toISOString()
    };
    const res = await fetchT(SYNC.url + '/rest/v1/fl_shared?on_conflict=id', {
      method: 'POST',
      headers: Object.assign({}, headers, { Prefer: 'resolution=merge-duplicates,return=minimal' }),
      body: JSON.stringify([payload])
    });
    if (res.ok) localStorage.setItem(LAST_HEARTBEAT_KEY, String(Date.now()));
  }

  async function fetchAllDevices() {
    const headers = await syncHeaders();
    const res = await fetchT(SYNC.url + '/rest/v1/fl_shared?kind=eq.device&select=id,data&deleted=is.false&order=updated.desc', { headers });
    if (!res.ok) throw new Error('Could not load devices');
    const rows = await res.json();
    /* the id comes along now so a dead device can be cleared off the list */
    return rows.map(r => Object.assign({ _id: r.id }, r.data));
  }

  /* Forget a device that no longer exists. It only removes the listing — it does
     not touch any data that device ever created. A live device reappears on its
     next heartbeat, which is the correct behaviour. */
  async function removeDevice(rowId) {
    const headers = await syncHeaders();
    const res = await fetchT(SYNC.url + '/rest/v1/fl_shared?on_conflict=id', {
      method: 'POST',
      headers: Object.assign({}, headers, { Prefer: 'resolution=merge-duplicates,return=minimal' }),
      body: JSON.stringify([{ id: rowId, kind: 'device', data: { removed: true },
                              deleted: true, updated: new Date().toISOString() }])
    });
    if (!res.ok) throw new Error('Could not remove that device');
    if (currentUser()) recordEvent('Device removed from list: ' + rowId.replace(/^device_/, ''), currentUser().name);
  }

  function recordEvent(type, who) {
    const entry = { id: 'log_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6), type, who, device: deviceName(), time: new Date().toISOString() };
    const log = JSON.parse(localStorage.getItem(LOG_KEY) || '[]');
    log.unshift(entry);
    localStorage.setItem(LOG_KEY, JSON.stringify(log.slice(0, 500)));
    markDirty(entry.id);   /* synced across devices — see syncNow()'s 'log' kind */
    scheduleSync();
    /* Email alerts. Until now EVERY log line was queued — about 12 a day — and
       since the mail service was never configured, 50 of them just sat there
       forever. Queue only what is worth an email, and only if alerts are on. */
    if (worthEmailing(entry)) {
      const q = JSON.parse(localStorage.getItem(MAILQ_KEY) || '[]');
      q.push(entry);
      localStorage.setItem(MAILQ_KEY, JSON.stringify(q.slice(-50)));
      flushMailQueue();
    }
  }

  /* 'off' (default) queues nothing · 'important' is deletions, CEO approvals and a
     login from a device we have not seen before · 'all' is everything. */
  const SEEN_DEVICES_KEY = 'fl_seen_devices';
  function worthEmailing(entry) {
    const mode = appSettings().emailMode;
    if (mode === 'off' || !mode) return false;
    if (mode === 'all') return true;
    const t = String(entry.type || '');
    if (/deleted/i.test(t)) return true;
    if (/approved|rejected/i.test(t)) return true;
    if (/^Logged in/.test(t)) {
      try {
        const seen = JSON.parse(localStorage.getItem(SEEN_DEVICES_KEY) || '[]');
        if (seen.indexOf(entry.device) === -1) {
          seen.push(entry.device);
          localStorage.setItem(SEEN_DEVICES_KEY, JSON.stringify(seen.slice(-20)));
          return true;                 /* first time we have seen this device */
        }
      } catch (e) { /* if we cannot tell, stay quiet rather than spam */ }
    }
    return false;
  }

  async function flushMailQueue() {
    if (!EMAILJS.publicKey || !EMAILJS.serviceId || !EMAILJS.templateId) return;
    if (!navigator.onLine) return;
    let q = JSON.parse(localStorage.getItem(MAILQ_KEY) || '[]');
    while (q.length) {
      const e = q[0];
      try {
        const res = await fetchT('https://api.emailjs.com/api/v1.0/email/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            service_id: EMAILJS.serviceId,
            template_id: EMAILJS.templateId,
            user_id: EMAILJS.publicKey,
            template_params: {
              event_type: e.type,
              user_name: e.who,
              device_info: e.device,
              event_time: new Date(e.time).toLocaleString('en-GB')
            }
          })
        });
        if (!res.ok) break;
        q.shift();
        localStorage.setItem(MAILQ_KEY, JSON.stringify(q));
      } catch (err) { break; }
    }
  }

  function activityLog() { return JSON.parse(localStorage.getItem(LOG_KEY) || '[]'); }
  /* public alias so pages can log + email custom notifications (approvals etc.) */
  const notify = recordEvent;

  /* ── Per-user documents ──────────────────────────────────── */
  function docsKey() { return 'fl_docs_' + currentUser().id; }
  function docs() { return JSON.parse(localStorage.getItem(docsKey()) || '[]'); }
  function getDoc(id) { return docs().find(x => x.id === id) || null; }
  function saveDoc(doc) {
    const d = docs();
    doc.updated = new Date().toISOString();
    const i = d.findIndex(x => x.id === doc.id);
    if (i >= 0) d[i] = doc; else d.unshift(doc);
    localStorage.setItem(docsKey(), JSON.stringify(d));
  }
  function deleteDoc(id) {
    localStorage.setItem(docsKey(), JSON.stringify(docs().filter(x => x.id !== id)));
  }

  /* try to send any queued alerts whenever a page opens */
  setTimeout(flushMailQueue, 1500);

  /* ── Branded modal dialogs ───────────────────────────────────
     Electron doesn't implement window.prompt() (only alert/confirm),
     so it silently never appears there; and the native alert/confirm
     boxes clash with the app's branding everywhere else. These replace
     all three with one consistent, promise-based, boutique-styled modal. */
  function injectModalStyles() {
    if (document.getElementById('fl-modal-style')) return;
    const s = document.createElement('style');
    s.id = 'fl-modal-style';
    s.textContent =
      '.fl-modal-mask{position:fixed;inset:0;background:rgba(58,2,16,.45);display:flex;align-items:center;justify-content:center;z-index:10000;padding:20px;font-family:"Lato",Arial,sans-serif;}' +
      '.fl-modal-box{background:#fff;border-radius:4px;padding:20px;width:100%;max-width:340px;box-shadow:0 12px 40px rgba(0,0,0,.3);}' +
      '.fl-modal-box p{font-size:13.5px;color:#2E2522;margin-bottom:16px;line-height:1.5;white-space:pre-wrap;}' +
      '.fl-modal-box input{width:100%;padding:10px 12px;border:1px solid #E8DDD8;border-radius:2px;font-size:14px;font-family:"Lato",Arial,sans-serif;margin:-6px 0 16px;outline:none;box-sizing:border-box;}' +
      '.fl-modal-box input:focus{border-color:#550318;}' +
      '.fl-modal-actions{display:flex;justify-content:flex-end;gap:8px;}' +
      '.fl-modal-actions button{padding:9px 16px;border-radius:2px;font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;cursor:pointer;font-family:inherit;border:1px solid #E8DDD8;background:#F6F4F0;color:#2E2522;}' +
      '.fl-modal-actions button.primary{background:#550318;color:#E6CCA1;border-color:#550318;}';
    document.head.appendChild(s);
  }
  function flAlert(message) {
    injectModalStyles();
    return new Promise(resolve => {
      const mask = document.createElement('div');
      mask.className = 'fl-modal-mask';
      mask.innerHTML = '<div class="fl-modal-box"><p></p><div class="fl-modal-actions"><button class="primary" id="flA-ok">OK</button></div></div>';
      mask.querySelector('p').textContent = message;
      document.body.appendChild(mask);
      const ok = mask.querySelector('#flA-ok');
      ok.focus();
      const done = () => { mask.remove(); resolve(); };
      ok.onclick = done;
      mask.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === 'Escape') done(); });
    });
  }
  function flConfirm(message, okWord, cancelWord, emphasis) {
    injectModalStyles();
    return new Promise(resolve => {
      const mask = document.createElement('div');
      mask.className = 'fl-modal-mask';
      const keep = emphasis === 'cancel' ? 'cancel' : 'ok';
      mask.innerHTML = '<div class="fl-modal-box"><p></p><div class="fl-modal-actions">' +
        '<button class="' + (keep === 'cancel' ? 'primary' : '') + '" id="flC-cancel"></button>' +
        '<button class="' + (keep === 'ok' ? 'primary' : '') + '" id="flC-ok"></button></div></div>';
      mask.querySelector('#flC-ok').textContent = okWord || 'OK';
      mask.querySelector('#flC-cancel').textContent = cancelWord || 'Cancel';
      mask.querySelector('p').textContent = message;
      document.body.appendChild(mask);
      const done = (v) => { mask.remove(); resolve(v); };
      mask.querySelector('#flC-ok').onclick = () => done(true);
      mask.querySelector('#flC-cancel').onclick = () => done(false);
      mask.addEventListener('keydown', e => { if (e.key === 'Escape') done(false); });
    });
  }
  function flPrompt(message, defaultValue) {
    injectModalStyles();
    return new Promise(resolve => {
      const mask = document.createElement('div');
      mask.className = 'fl-modal-mask';
      mask.innerHTML = '<div class="fl-modal-box"><p></p><input type="text" id="flP-input"><div class="fl-modal-actions"><button id="flP-cancel">Cancel</button><button class="primary" id="flP-ok">OK</button></div></div>';
      mask.querySelector('p').textContent = message;
      const input = mask.querySelector('#flP-input');
      input.value = defaultValue || '';
      document.body.appendChild(mask);
      input.focus(); input.select();
      const done = (v) => { mask.remove(); resolve(v); };
      mask.querySelector('#flP-ok').onclick = () => done(input.value);
      mask.querySelector('#flP-cancel').onclick = () => done(null);
      input.addEventListener('keydown', e => {
        if (e.key === 'Enter') done(input.value);
        if (e.key === 'Escape') done(null);
      });
    });
  }

  /* ── PDF export ──────────────────────────────────────────
     Desktop (Electron/browser) already has a working native print-to-PDF
     dialog via window.print(), so that stays untouched. Android's WebView
     has NO print support at all — window.print() silently does nothing
     there — so on Android we render the document to a PDF ourselves
     (jsPDF + html2canvas, bundled offline in www/vendor/), save a real
     copy to the device's Documents folder, then open the native Share
     sheet so the user can send it immediately too. Requires the calling
     page to load vendor/jspdf.umd.min.js + vendor/html2canvas.min.js. */
  function isAndroidApp() {
    return !!(window.Capacitor && Capacitor.getPlatform && Capacitor.getPlatform() === 'android');
  }
  /* a long item list needs a taller page, not smaller text — CSS zoom (an earlier
     attempt at this) resizes the real layout box, and on some Android WebView
     builds that corrupts text shaping (missing spaces, dropped characters).
     Growing the PAGE height to match the content instead never touches the
     DOM's own layout, so nothing about how the text renders can change.
     Never shrinks below a standard A4 height — only grows past it. */
  function exportPageSize(el) {
    const A4W = 595.28, A4H = 841.89;
    const naturalH = A4W * (el.scrollHeight / el.scrollWidth) * 1.02;
    return { width: A4W, height: Math.max(A4H, naturalH) };
  }
  async function exportPdf(el, filename) {
    if (!window.jspdf || !window.html2canvas) {
      /* only the three editor pages load them; anything else still prints */
      window.print();
      return;
    }
    const hideStyle = document.createElement('style');
    hideStyle.textContent = '.no-print{display:none!important;}';
    document.head.appendChild(hideStyle);
    try {
      const { width: pageWidth, height: pageHeight } = exportPageSize(el);
      /* jsPDF's own .html() plugin has internal pagination logic that ignores a
         custom page height entirely (confirmed: still split into 2 pages even
         with autoPaging off and a page tall enough for everything) — capturing
         with html2canvas directly and placing that single image ourselves
         sidesteps its pagination logic altogether. */
      const scale = (pageWidth / el.scrollWidth) * 1.5;
      const canvas = await html2canvas(el, { scale, windowWidth: el.scrollWidth, useCORS: true });
      const { jsPDF } = window.jspdf;
      const pdf = new jsPDF({ unit: 'pt', format: [pageWidth, pageHeight] });
      pdf.addImage(canvas.toDataURL('image/jpeg', 0.92), 'JPEG', 0, 0, pageWidth, pageHeight);
      if (isAndroidApp()) {
        const base64 = pdf.output('datauristring').split(',')[1];
        const written = await Capacitor.Plugins.Filesystem.writeFile({
          path: filename, data: base64, directory: 'DOCUMENTS', recursive: true
        });
        await Capacitor.Plugins.Share.share({ title: filename, url: written.uri, dialogTitle: 'Save or send ' + filename });
      } else {
        pdf.save(filename);   /* PC: the browser's own save dialog */
      }
    } catch (e) {
      await flAlert('Could not save the PDF: ' + (e.message || e));
    } finally {
      hideStyle.remove();
    }
  }

  /* ══════════════════ ADMIN PANEL SUPPORT ══════════════════
     Everything below only feeds the Admin panel. None of it changes how events,
     the tracker, expense sheets or Jo's approvals behave. */


  /* what the update server is currently offering, for the version card */
  async function publishedVersion() {
    const res = await fetchT(UPDATE_BASE + '/latest.json?t=' + Date.now(), { cache: 'no-store' });
    if (!res.ok) throw new Error('update server returned ' + res.status);
    const j = await res.json();
    return { version: j.version, notes: j.notes, upToDate: verCmp(j.version, APP_VERSION) <= 0 };
  }

  /* how full each store is. The small box is the one that broke in Aug 2026. */
  async function storageStats() {
    let used = 0;
    const items = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      const n = (localStorage.getItem(k) || '').length;
      used += n;
      if (n > 1024) items.push({ key: k, bytes: n });
    }
    items.sort((a, b) => b.bytes - a.bytes);
    let photos = 0, photoBytes = 0;
    try {
      const blob = await idbGet(EVENTS_KEY);
      if (typeof blob === 'string') {
        photoBytes = blob.length;
        photos = (blob.match(/"data:image/g) || []).length;
      }
    } catch (e) { /* IndexedDB unavailable — report what we can */ }
    return { used, limit: 5 * 1024 * 1024, pct: used / (5 * 1024 * 1024) * 100,
             items: items.slice(0, 6), photoBytes, photos };
  }

  /* The same checks I run by hand when Sajith asks "is everything okay?" */
  /* Shared by the CEO dashboard and the admin home strip, so the two can never
     disagree. An enquiry only counts as pipeline if it is still open AND its event
     date has not already gone by — a quote for last month's party is not money
     coming in. Ones with no date at all are kept apart rather than guessed about. */
  function enquiryBuckets() {
    const today = new Date().toISOString().slice(0, 10);
    const val = e => parseFloat(e.quoteValue) || 0;
    const open = enquiriesAll().filter(enquiryIsOpen);
    const live = open.filter(e => e.eventDate && e.eventDate >= today);
    const undated = open.filter(e => !e.eventDate);
    const gone = open.filter(e => e.eventDate && e.eventDate < today);
    const sum = a => a.reduce((s, e) => s + val(e), 0);
    return { live, liveValue: sum(live),
             undated, undatedValue: sum(undated),
             gone, goneValue: sum(gone) };
  }

  /* Confirmed orders by month, split into already delivered and still ahead.
     Only months from the current one onward — earlier months are finished and
     already shown on the dashboard's own charts. */
  function bookedByMonth() {
    const today = new Date().toISOString().slice(0, 10);
    const thisMonth = today.slice(0, 7);
    const after = t => (t.revenue || 0) * (1 - (t.discountPct || 0) / 100);
    const by = {};
    trackerAll().forEach(t => {
      if (!t.eventDate) return;
      const m = t.eventDate.slice(0, 7);
      if (m < thisMonth) return;
      by[m] = by[m] || { month: m, done: 0, doneCount: 0, todo: 0, todoCount: 0 };
      if (t.eventDate < today) { by[m].done += after(t); by[m].doneCount++; }
      else { by[m].todo += after(t); by[m].todoCount++; }
    });
    return Object.keys(by).sort().map(m => by[m]);
  }

  /* ── Tidy the shared activity history ────────────────────────────────
     The cloud keeps every log line for ever while each device displays only
     its newest 500 — so the oldest ones are invisible everywhere yet still
     count against the 1,000-row limit a full download stops at. That limit
     is what let a half-loaded device overwrite the June sheet.
     This is the first DELETE the app has ever sent, so it reports what the
     server actually said instead of assuming it was allowed. */
  async function tidyActivityHistory(keep) {
    const n = Math.max(50, parseInt(keep, 10) || 400);
    try {
      const headers = await syncHeaders();
      const base = SYNC.url + '/rest/v1/fl_shared';
      /* everything past the newest n, oldest first, in bounded batches */
      const res = await fetchT(base + '?select=id&kind=eq.log&order=updated.desc&offset=' + n + '&limit=500', { headers });
      if (!res.ok) return { ok: false, error: 'could not list (' + res.status + ')', removed: 0 };
      const old = await res.json();
      if (!old.length) return { ok: true, removed: 0, kept: n };
      let removed = 0;
      for (let i = 0; i < old.length; i += 100) {
        const ids = old.slice(i, i + 100).map(r => r.id);
        const url = base + '?kind=eq.log&id=in.(' + ids.map(encodeURIComponent).join(',') + ')';
        const del = await fetchT(url, { method: 'DELETE', headers: Object.assign({}, headers, { Prefer: 'return=minimal' }) });
        if (!del.ok) {
          return { ok: false, removed: removed,
                   error: del.status === 401 || del.status === 403
                     ? 'not allowed to delete (' + del.status + ')'
                     : 'delete failed (' + del.status + ')' };
        }
        removed += ids.length;
      }
      /* trim this device's own copy to match, so the two agree immediately */
      const keptIds = new Set(old.map(r => r.id.replace(/^log_/, '')));
      const mine = activityLog().filter(e => !keptIds.has(e.id));
      localStorage.setItem(LOG_KEY, JSON.stringify(mine.slice(0, 500)));
      if (currentUser()) recordEvent('Old activity history tidied: ' + removed + ' lines removed', currentUser().name);
      return { ok: true, removed: removed, kept: n };
    } catch (e) {
      return { ok: false, removed: 0, error: 'could not reach the server' };
    }
  }

  function dataCheck() {
    const today = new Date().toISOString().slice(0, 10);
    const evs = eventsAll(), trk = trackerAll(), enq = enquiriesAll();
    const out = [];
    const add = (ok, text, detail) => out.push({ ok, text, detail: detail || '' });

    const blanks = evs.filter(e => !(e.name || '').trim() && !(e.orderNo || '').trim());
    add(!blanks.length, evs.length + ' event sheets', blanks.length ? blanks.length + ' are blank' : 'no blanks');

    const seenId = {}, dupId = [];
    evs.forEach(e => { if (seenId[e.id]) dupId.push(e.id); seenId[e.id] = 1; });
    const byOrder = {};
    evs.forEach(e => { const k = (e.orderNo || '').trim(); if (k) byOrder[k] = (byOrder[k] || 0) + 1; });
    const dupOrder = Object.keys(byOrder).filter(k => byOrder[k] > 1);
    add(!dupId.length && !dupOrder.length, 'No duplicate event sheets',
        dupOrder.length ? 'order ' + dupOrder.join(', ') + ' appears twice' : '');

    const tOrder = {};
    trk.forEach(r => { const k = (r.orderNo || '').trim(); if (k) tOrder[k] = (tOrder[k] || 0) + 1; });
    const tDup = Object.keys(tOrder).filter(k => tOrder[k] > 1);
    add(!tDup.length, trk.length + ' tracker orders',
        tDup.length ? 'order ' + tDup.join(', ') + ' logged twice' : 'no duplicates');

    const unrev = evs.filter(e => e.date && e.date < today &&
      !(e.approval && ['approved', 'rejected'].includes(e.approval.status)));
    add(!unrev.length, 'Approvals up to date',
        unrev.length ? unrev.length + ' finished events still waiting for the CEO' : 'nothing waiting');

    const onSheet = new Set(evs.map(e => (e.orderNo || '').trim()).filter(Boolean));
    const noSheet = trk.filter(t => t.eventDate && t.eventDate < today && !onSheet.has((t.orderNo || '').trim()));
    const value = noSheet.reduce((s, t) => s + (t.revenue || 0) * (1 - (t.discountPct || 0) / 100), 0);
    add(!noSheet.length, 'Every finished order has a GP sheet',
        noSheet.length ? noSheet.length + ' finished events have no sheet — AED ' +
          Math.round(value).toLocaleString() + ' uncosted' : '');

    const due = enq.filter(e => e.followUpDate && e.followUpDate <= today && enquiryIsOpen(e));
    add(!due.length, 'Enquiry follow-ups', due.length ? due.length + ' are overdue' : 'none overdue');

    const dirty = dirtySet().size;
    add(!dirty, 'Everything uploaded',
        dirty ? dirty + (dirty === 1 ? ' item is' : ' items are') + ' still waiting to upload' : 'nothing waiting');

    return out;
  }

  /* Who can open what. Kept here beside the role helpers so it lives with the
     rules it describes — it is still a written list, not magically derived. */
  const PERMISSIONS = [
    { page: 'Dashboard',                     roles: ['admin', 'finance', 'ceo'] },
    { page: 'Event GP Sheets',               roles: ['admin', 'finance', 'ceo'] },
    { page: 'Tracker — client name & mobile', roles: ['admin'] },
    { page: 'Tracker — "Full view"',         roles: ['admin'] },
    { page: 'Event Enquiries',               roles: ['admin', 'ceo'] },
    { page: 'Event Calendar',                roles: ['admin', 'ceo'] },
    { page: 'Client Occasions',              roles: ['admin'] },
    { page: 'Expense Sheets',                roles: ['admin', 'finance', 'ceo'] },
    { page: 'Quotations & Proposals',        roles: ['admin', 'finance', 'ceo', 'staff'] },
    { page: 'Admin Panel',                   roles: ['admin'] }
  ];
  function permissions() { return PERMISSIONS.map(p => ({ page: p.page, roles: p.roles.slice() })); }

  /* One file with everything on this device, for safekeeping off the cloud. */
  async function exportBackup() {
    const out = { app: APP_VERSION, taken: new Date().toISOString(), device: deviceName(), data: {} };
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k.indexOf('fl_') !== 0) continue;
      if (k === SESSION_KEY) continue;            /* never put a login token in a file */
      out.data[k] = localStorage.getItem(k);
    }
    try {
      const full = await idbGet(EVENTS_KEY);      /* the real events, photos and all */
      if (typeof full === 'string') out.data[EVENTS_KEY] = full;
    } catch (e) { /* fall back to the photo-free mirror already copied above */ }
    return out;
  }

  return { register, login, logout, currentUser, guard, docs, getDoc, saveDoc, deleteDoc, activityLog, notify,
    appSettings, setAppSetting, appVersion, publishedVersion, storageStats, dataCheck,
    whatsNewFor, renderWhatsNew, markWhatsNewSeen,
    permissions, exportBackup, enquiryBuckets, bookedByMonth,
    knownAccounts,
    role, isAdmin, canFinance, isCeo, guardRole,
    adminSetRole, adminSetDisabled, adminDeleteUser, fetchAllProfiles, fetchAllDevices, removeDevice,
    requestPasswordReset, confirmPasswordReset, confirmSignup,
    eventsAll, eventGet, eventSave, eventDelete, eventsLoaded, whenReady, hydratePhotos,
    trackerAll, trackerSave, trackerDelete,
    occasionsAll, occasionSave, occasionDelete,
    enquiriesAll, enquirySave, enquiryDelete,
    allStatuses, statusMetaOf, statusGroup, enquiryIsOpen, addCustomStatus, removeCustomStatus,
    statusInUse, STATUS_GROUPS, BUILT_IN_STATUSES, tidyActivityHistory, enquiryWon,
    enquiryState, LOST_REASONS, guessLostReason, lostReasonOf,
    calendarAll, calendarSave, calendarDelete, calendarAddComment,
    quotesAll, quoteGet, quoteSave, quoteDelete,
    proposalsAll, proposalGet, proposalSave, proposalDelete,
    expensesAll, expenseGet, expenseSave, expenseDelete,
    expenseCutoffDate, expenseCutoffPassed, expenseLineItemsForMonth, expenseMonthFullyApproved, expenseSheetStale, calcEventCommission,
    autoGenerateExpenseSheets, adminSignature, setAdminSignature,
    monthlyOverrides, setMonthlyOverride, companyIncome, setCompanyIncome,
    syncNow, onSync, syncEnabled, storageIsFull,
    checkForUpdate, _updateBanner: showUpdateBanner,
    deviceName, setDeviceName, deviceId,
    flAlert, flConfirm, flPrompt, exportPdf, isAndroidApp };
})();
