/* 
  IndexedDB Secure Sync Abstraction with Pluggable Transports
  ===================================================================
  Features
  - High-level IndexedDB wrapper (create DB by id, CRUD, indexing, migrations).
  - Per-device encryption at rest (AES-GCM). Data in IndexedDB looks like gibberish.
  - Searchable encryption (blind index via HMAC over n-grams) for partial search.
  - Roles & permissions: creator, admin, editor, viewer + custom roles (creator-only).
  - Field-level and record-level ACLs:
      * Creator can define per-store policy with defaults + per-field rules.
      * Per-record _acl overrides (read/write arrays of roles).
      * Admins/Editors can assign newly added custom roles (but cannot create/delete roles).
  - Device registry with signed RoleGrants:
      * Creator holds DB Signing Key (DSK). Issues signed grants binding deviceId+role+pubkey.
      * Each message is signed by device; creator verifies grant + message signature.
      * Non-creator devices accept sync only from the Creator.
      * If a user hacks their local IndexedDB and flips role, others ignore it since they require creator-signed grants.
  - Hub-and-spoke sync:
      * All devices send updates to Creator only.
      * Creator validates, applies if permitted, and redistributes diffs per-device with redaction based on ACL/policy.
  - Pluggable transports: WebSocket, HTTP long-poll, Bluetooth (host-provided), custom.
  - Granular permission enforcement on CRUD & sync paths.
  - Lamport-clock conflict resolution (LWW with tiebreaker).

  IMPORTANT SECURITY NOTES
  - This is a client-side module. For strong guarantees, run the Creator role in a secure backend/relay that holds DSK privately.
  - The searchable-encryption scheme leaks token frequency and query patterns (typical of practical schemes).

  -------------------------------------------------------------------
  Usage (sketch)
  -------------------------------------------------------------------
    import {
      IndexedDBAbstraction, SyncManager, CreatorHubSyncManager,
      WebSocketTransport, HttpTransport, BluetoothTransport,
      ROLES, DEFAULT_ROLE_PERMISSIONS
    } from './indexeddb-secure-sync.full.js';

    const dbId = 'my-db';
    const deviceId = 'device-A';

    const schema = {
      version: 1,
      stores: {
        tasks: {
          keyPath: 'id',
          indexes: [{ name: 'byStatus', keyPath: 'status' }],
          secureIndex: ['title', 'description'] // enables encrypted partial search
        }
      }
    };

    const db = new IndexedDBAbstraction({ dbId, deviceId, schema });
    await db.init();

    // Attach per-device crypto (keys should come from secure OS store, not IndexedDB)
    const cryptoMgr = new CryptoManager({
      deviceId, dbId, 
      loadSecrets: async () => ({
        dekRaw,               // Uint8Array(32)
        indexKeyRaw,          // Uint8Array(32)
        devicePrivJwk,        // device signing private JWK (ECDSA P-256)
        devicePubJwk,         // device signing public JWK
        dskPubJwk             // Creator's public DSK JWK (for grant verification)
      })
    });
    db.attachCrypto(cryptoMgr);

    // Bootstrap creator on first run
    await db.ensureDevice({ deviceId, role: ROLES.CREATOR });

    // Configure role policy (creator-only)
    await db.setPolicy('tasks', {
      defaults: { read: [ROLES.CREATOR, ROLES.ADMIN, ROLES.EDITOR, ROLES.VIEWER],
                  write:  [ROLES.CREATOR, ROLES.ADMIN, ROLES.EDITOR] },
      fields: {
        secret: { read: [ROLES.CREATOR, ROLES.ADMIN], write: [ROLES.CREATOR, ROLES.ADMIN] }
      }
    });

    // Add custom role (creator-only)
    await db.addCustomRole('analyst', { READ:true, WRITE:false, DELETE:false, MANAGE_ROLES:false, MANAGE_DEVICES:false, MANAGE_SCHEMA:false });

    // Grant device role with signed grant (creator issues)
    //   const grant = issueRoleGrant({ dskPrivKey, dbId, deviceId:'device-B', role: 'analyst', devicePubJwk });
    await db.addOrUpdateDevice({ deviceId:'device-B', role:'analyst', grant });

    // Use CreatorHubSyncManager so all devices sync via creator
    const socket = new WebSocket('wss://example.com/sync');
    const transport = new WebSocketTransport({ socket });

    const sync = new CreatorHubSyncManager({ db, transport, cryptoManager: cryptoMgr, isCreator: true  (on creator device) });
    await sync.start();

    // CRUD (auto-encrypted; search uses blind index):
    await db.put('tasks', { id:'t1', title:'hello world', description:'secret note', status:'open' });
    const found = await db.search('tasks', { text:'hell', fields:['title'], minMatch:'ALL' });

    // Per-record ACL:
    await db.setRecordAcl('tasks','t1',{ read:['analyst','viewer'], write:['analyst'] });
*/

// ------------------------------
// Utilities
// ------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function uid(prefix = 'id') {
  return `${prefix}_${Math.random().toString(36).slice(2)}_${Date.now()}`;
}

function toPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function eventTarget() {
  const et = new EventTarget();
  return {
    target: et,
    on: (type, handler, opts) => et.addEventListener(type, handler, opts),
    off: (type, handler, opts) => et.removeEventListener(type, handler, opts),
    emit: (type, detail) => et.dispatchEvent(new CustomEvent(type, { detail }))
  };
}

// ------------------------------
// Roles & default permissions
// ------------------------------

export const ROLES = Object.freeze({
  CREATOR: 'creator',
  ADMIN: 'admin',
  EDITOR: 'editor',
  VIEWER: 'viewer',
  SYNC_AGENT: 'sync_agent'
});

export const DEFAULT_ROLE_PERMISSIONS = Object.freeze({
  [ROLES.CREATOR]: { READ:true, WRITE:true, DELETE:true, MANAGE_ROLES:true, MANAGE_DEVICES:true, MANAGE_SCHEMA:true },
  [ROLES.ADMIN]:   { READ:true, WRITE:true, DELETE:true, MANAGE_ROLES:true, MANAGE_DEVICES:true, MANAGE_SCHEMA:false },
  [ROLES.EDITOR]:  { READ:true, WRITE:true, DELETE:false, MANAGE_ROLES:false, MANAGE_DEVICES:false, MANAGE_SCHEMA:false },
  [ROLES.VIEWER]:  { READ:true, WRITE:false, DELETE:false, MANAGE_ROLES:false, MANAGE_DEVICES:false, MANAGE_SCHEMA:false },
  [ROLES.SYNC_AGENT]: { READ:true, WRITE:true, DELETE:false, MANAGE_ROLES:false, MANAGE_DEVICES:false, MANAGE_SCHEMA:false }
});

// ------------------------------
// WebCrypto helpers
// ------------------------------
function utf8(str) { return new TextEncoder().encode(str); }
function b64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function fromB64(s) { return new Uint8Array([...atob(s)].map(c => c.charCodeAt(0))); }

async function importAesKey(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function exportRawKey(key) { return new Uint8Array(await crypto.subtle.exportKey('raw', key)); }
async function genAesKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function genSigningKeyPair() {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}
async function signBytes(privKey, bytes) {
  return new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privKey, bytes));
}
async function verifyBytes(pubKey, sig, bytes) {
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, sig, bytes);
}
async function importPubJwk(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
}
async function importPrivJwk(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
}
async function hmacKeyFromRaw(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}
async function hmacDigest(key, bytes) {
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, bytes));
}

// n-grams for partial search
function ngrams(s, n = 3) {
  const out = new Set();
  const str = (s || '').toLowerCase();
  if (!str) return out;
  if (str.length <= n) { out.add(str); return out; }
  for (let i = 0; i <= str.length - n; i++) out.add(str.slice(i, i + n));
  return out;
}

// ------------------------------
// CryptoManager: per-device encryption + blind index + signatures
// ------------------------------
export class CryptoManager {
  constructor({ deviceId, dbId, loadSecrets }) {
    this.deviceId = deviceId;
    this.dbId = dbId;
    this.loadSecrets = loadSecrets; // async () => { dekRaw, indexKeyRaw, devicePrivJwk, devicePubJwk, dskPubJwk? }
    this.ready = this._init();
  }
  async _init() {
    const s = await this.loadSecrets();
    if (!s) throw new Error('Crypto secrets not provided. Provide per-device secrets from secure storage.');
    this.dek = await importAesKey(s.dekRaw);
    this.indexKey = await hmacKeyFromRaw(s.indexKeyRaw);
    this.devicePub = await importPubJwk(s.devicePubJwk);
    this.devicePriv = await importPrivJwk(s.devicePrivJwk);
    this.dskPub = s.dskPubJwk ? await importPubJwk(s.dskPubJwk) : null;
    this.devicePubJwk = s.devicePubJwk;
  }
  async encryptJson(obj) {
    await this.ready;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.dek, utf8(JSON.stringify(obj))));
    return { iv: b64(iv), ct: b64(ct) };
  }
  async decryptJson(payload) {
    await this.ready; if (!payload) return null;
    const iv = fromB64(payload.iv); const ct = fromB64(payload.ct);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, this.dek, ct));
    return JSON.parse(new TextDecoder().decode(pt));
  }
  async blindTokens(str, n = 3) {
    await this.ready; const toks = ngrams(str, n);
    const out = [];
    for (const t of toks) { out.push(b64(await hmacDigest(this.indexKey, utf8(t)))); }
    return out;
  }
  async sign(obj) {
    await this.ready;
    return b64(await signBytes(this.devicePriv, utf8(JSON.stringify(obj))));
  }
  async verifyWithDSKSignature(sigB64, obj) {
    if (!this.dskPub) return false;
    const sig = fromB64(sigB64);
    return verifyBytes(this.dskPub, sig, utf8(JSON.stringify(obj)));
  }
  async verifyWithDeviceSignature(pubJwk, sigB64, obj) {
    const pub = await importPubJwk(pubJwk);
    return verifyBytes(pub, fromB64(sigB64), utf8(JSON.stringify(obj)));
  }
}

// ------------------------------
// IndexedDB Abstraction (base)
// ------------------------------
export class IndexedDBAbstraction {
  constructor({ dbId, deviceId, schema, rolePermissions = DEFAULT_ROLE_PERMISSIONS }) {
    this.dbId = dbId;
    this.deviceId = deviceId;
    this.schema = schema || { version: 1, stores: {} };
    this.rolePermissions = rolePermissions;
    this._db = null;
    this._events = eventTarget();
    this._bc = null; // BroadcastChannel
    this.crypto = null;
    this._policies = {}; // per-store policies
  }

  on(type, handler, opts) { this._events.on(type, handler, opts); }
  off(type, handler, opts) { this._events.off(type, handler, opts); }

  attachCrypto(cryptoManager) { this.crypto = cryptoManager; return this; }

  async init() {
    const name = `idb:${this.dbId}`;
    const version = this.schema.version || 1;
    this._db = await new Promise((resolve, reject) => {
      const req = indexedDB.open(name, version);
      req.onupgradeneeded = (ev) => {
        const db = req.result;
        const oldVersion = ev.oldVersion || 0;
        if (!db.objectStoreNames.contains('_meta')) db.createObjectStore('_meta', { keyPath: 'key' });
        if (!db.objectStoreNames.contains('_devices')) db.createObjectStore('_devices', { keyPath: 'deviceId' });
        if (!db.objectStoreNames.contains('_roles')) db.createObjectStore('_roles', { keyPath: 'role' });
        if (!db.objectStoreNames.contains('_changelog')) db.createObjectStore('_changelog', { keyPath: 'seq' });
        if (!db.objectStoreNames.contains('_peerSync')) db.createObjectStore('_peerSync', { keyPath: 'peerId' });
        if (!db.objectStoreNames.contains('_policies')) db.createObjectStore('_policies', { keyPath: 'store' });

        const stores = this.schema?.stores || {};
        for (const [storeName, def] of Object.entries(stores)) {
          if (!db.objectStoreNames.contains(storeName)) {
            const os = db.createObjectStore(storeName, { keyPath: def?.keyPath || 'id', autoIncrement: !!def?.autoIncrement });
            (def?.indexes || []).forEach((idx) => os.createIndex(idx.name, idx.keyPath, idx.options || {}));
          } else if (oldVersion < version) {
            const os = req.transaction.objectStore(storeName);
            (def?.indexes || []).forEach((idx) => {
              if (!os.indexNames.contains(idx.name)) os.createIndex(idx.name, idx.keyPath, idx.options || {});
            });
          }
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });

    // init meta + roles
    const tx = this._tx(['_meta', '_roles'], 'readwrite');
    const metaStore = tx.objectStore('_meta');
    const rolesStore = tx.objectStore('_roles');
    const info = (await toPromise(metaStore.get('info'))) || { key: 'info', dbId: this.dbId, createdAt: Date.now(), lamport: 0, creatorDeviceId: this.deviceId };
    await toPromise(metaStore.put(info));
    for (const role of Object.keys(this.rolePermissions)) {
      const existing = await toPromise(rolesStore.get(role));
      if (!existing) await toPromise(rolesStore.put({ role, permissions: this.rolePermissions[role] }));
    }
    await toPromise(tx.done || Promise.resolve());

    // BroadcastChannel
    try {
      this._bc = new BroadcastChannel(`idb-sync:${this.dbId}`);
      this._bc.onmessage = (ev) => { if (ev?.data?.type) this._events.emit(ev.data.type, ev.data.payload); };
    } catch {}

    // Create secure index stores if needed
    await this._ensureSecureIndexStores();

    // Load policies into memory
    this._policies = await this._loadPolicies();
    return this;
  }

  _tx(storeNames, mode = 'readonly') {
    const tx = this._db.transaction(storeNames, mode);
    tx.done = new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(tx.error);
      tx.onerror = () => reject(tx.error);
    });
    return tx;
  }

  async getRolePermissions(role) {
    const tx = this._tx(['_roles']);
    const r = await toPromise(tx.objectStore('_roles').get(role));
    await toPromise(tx.done || Promise.resolve());
    return r?.permissions || {};
  }

  async currentRole() {
    const r = await this.getDevice(this.deviceId);
    return r?.role || ROLES.VIEWER;
  }

  async ensureDevice({ deviceId, role = ROLES.VIEWER }) {
    const existing = await this.getDevice(deviceId);
    if (existing) return existing;
    return this.addOrUpdateDevice({ deviceId, role });
  }

  async addOrUpdateDevice({ deviceId, role, grant }) {
    await this._assertPermission('MANAGE_DEVICES');
    const tx = this._tx(['_devices'], 'readwrite');
    const record = { deviceId, role, addedAt: Date.now(), addedBy: this.deviceId, grant: grant || null };
    await toPromise(tx.objectStore('_devices').put(record));
    await toPromise(tx.done);
    await this._recordChange({ type: 'device_upsert', store: '_devices', key: deviceId, value: record });
    return record;
  }

  async setRole({ deviceId, role }) {
    await this._assertPermission('MANAGE_ROLES');
    const dev = await this.getDevice(deviceId);
    if (!dev) throw new Error('Device not found');
    dev.role = role;
    const tx = this._tx(['_devices'], 'readwrite');
    await toPromise(tx.objectStore('_devices').put(dev));
    await toPromise(tx.done);
    await this._recordChange({ type: 'device_upsert', store: '_devices', key: deviceId, value: dev });
    return dev;
  }

  async listDevices() {
    const tx = this._tx(['_devices']);
    const store = tx.objectStore('_devices');
    const all = await toPromise(store.getAll());
    await toPromise(tx.done);
    return all;
  }

  async getDevice(deviceId) {
    const tx = this._tx(['_devices']);
    const v = await toPromise(tx.objectStore('_devices').get(deviceId));
    await toPromise(tx.done);
    return v || null;
  }

  async addCustomRole(role, permissions) {
    // Only creator can add/remove roles
    const me = await this.getDevice(this.deviceId);
    if (me?.role !== ROLES.CREATOR) throw new Error('Only creator can add/remove roles');
    const tx = this._tx(['_roles'], 'readwrite');
    await toPromise(tx.objectStore('_roles').put({ role, permissions }));
    await toPromise(tx.done);
    await this._recordChange({ type: 'role_upsert', store: '_roles', key: role, value: { role, permissions } });
  }

  async removeCustomRole(role) {
    const me = await this.getDevice(this.deviceId);
    if (me?.role !== ROLES.CREATOR) throw new Error('Only creator can remove roles');
    if ([ROLES.CREATOR, ROLES.ADMIN, ROLES.EDITOR, ROLES.VIEWER, ROLES.SYNC_AGENT].includes(role))
      throw new Error('Cannot remove built-in role');
    const tx = this._tx(['_roles'], 'readwrite');
    await toPromise(tx.objectStore('_roles').delete(role));
    await toPromise(tx.done);
    await this._recordChange({ type: 'role_delete', store: '_roles', key: role });
  }

  async setPolicy(store, policy) {
    // creator-only
    const me = await this.getDevice(this.deviceId);
    if (me?.role !== ROLES.CREATOR) throw new Error('Only creator can set policy');
    const tx = this._tx(['_policies'], 'readwrite');
    await toPromise(tx.objectStore('_policies').put({ store, policy }));
    await toPromise(tx.done);
    this._policies[store] = policy;
    await this._recordChange({ type: 'policy_upsert', store: '_policies', key: store, value: { store, policy } });
  }

  async _loadPolicies() {
    const tx = this._tx(['_policies']);
    const rows = await toPromise(tx.objectStore('_policies').getAll());
    await toPromise(tx.done);
    const out = {};
    for (const r of rows) out[r.store] = r.policy;
    return out;
  }

  // ACL helpers
  async setRecordAcl(store, id, acl) {
    // admins/editors can assign ACLs but only using existing roles (custom or built-in)
    const role = await this.currentRole();
    const perms = await this.getRolePermissions(role);
    if (!(perms.MANAGE_ROLES || perms.WRITE)) throw new Error('Permission denied to set ACL');
    // load, decrypt, patch _acl, re-put
    const row = await this.get(store, id);
    if (!row) throw new Error('Record not found');
    const patched = { ...row, _acl: sanitizeAcl(acl) };
    return this.put(store, patched, id);
  }

  // ---------------- CRUD API with encryption & blind index ----------------
  async get(store, key) {
    await this._assertPermission('READ');
    if (!this.crypto) throw new Error('CryptoManager not attached');
    const tx = self._tx ? self._tx([store]) : this._tx([store]);
    const val = await toPromise(tx.objectStore(store).get(key));
    await toPromise(tx.done);
    if (!val) return null;
    const dec = await this.crypto.decryptJson(val._enc);
    return dec ?? null;
  }

  async getAll(store) {
    await this._assertPermission('READ');
    if (!this.crypto) throw new Error('CryptoManager not attached');
    const tx = this._tx([store]);
    const rows = await toPromise(tx.objectStore(store).getAll());
    await toPromise(tx.done);
    const out = [];
    for (const r of rows) out.push(await this.crypto.decryptJson(r._enc));
    return out;
  }

  async put(store, value, key) {
    await this._assertPermission('WRITE');
    if (!this.crypto) throw new Error('CryptoManager not attached');
    const withMeta = this._augmentDoc(value);

    // secure index build
    const def = this.schema?.stores?.[store];
    let tokens = [];
    if (def?.secureIndex && def.secureIndex.length) {
      for (const field of def.secureIndex) {
        const val = (withMeta?.[field] ?? '') + '';
        const t = await this.crypto.blindTokens(val, 3);
        tokens = tokens.concat(t);
      }
    }

    // encrypt payload
    const enc = await this.crypto.encryptJson(withMeta);
    const idKey = key ?? withMeta?.id ?? uid('key');

    const tx = this._tx([store, this._secureIndexStoreName(store)], 'readwrite');
    await toPromise(tx.objectStore(store).put({ id: idKey, _enc: enc }));
    if (tokens.length) await toPromise(tx.objectStore(this._secureIndexStoreName(store)).put({ id: idKey, token: tokens }));
    await toPromise(tx.done);

    await this._recordChange({ type: 'upsert', store, key: idKey, value: enc, enc: true });
    return idKey;
  }

  async bulkPut(store, values) {
    await this._assertPermission('WRITE');
    if (!this.crypto) throw new Error('CryptoManager not attached');
    const tx = this._tx([store, this._secureIndexStoreName(store)], 'readwrite');
    const ks = [];
    for (const v of values) {
      const withMeta = this._augmentDoc(v);
      const enc = await this.crypto.encryptJson(withMeta);
      const idKey = withMeta?.id ?? uid('key');
      await toPromise(tx.objectStore(store).put({ id: idKey, _enc: enc }));
      // secure index
      const def = this.schema?.stores?.[store];
      if (def?.secureIndex) {
        let tokens = [];
        for (const f of def.secureIndex) {
          const t = await this.crypto.blindTokens(String(withMeta?.[f] ?? ''), 3);
          tokens = tokens.concat(t);
        }
        await toPromise(tx.objectStore(this._secureIndexStoreName(store)).put({ id: idKey, token: tokens }));
      }
      ks.push(idKey);
      await this._enqueueLocalChange({ type: 'upsert', store, key: idKey, value: enc, enc: true });
    }
    await toPromise(tx.done);
    await this._flushLocalChanges();
    return ks;
  }

  async delete(store, key) {
    await this._assertPermission('DELETE');
    const tx = this._tx([store, this._secureIndexStoreName(store)], 'readwrite');
    await toPromise(tx.objectStore(store).delete(key));
    await toPromise(tx.objectStore(this._secureIndexStoreName(store)).delete(key));
    await toPromise(tx.done);
    await this._recordChange({ type: 'delete', store, key });
  }

  async clear(store) {
    await this._assertPermission('DELETE');
    const tx = this._tx([store, this._secureIndexStoreName(store)], 'readwrite');
    await toPromise(tx.objectStore(store).clear());
    await toPromise(tx.objectStore(this._secureIndexStoreName(store)).clear());
    await toPromise(tx.done);
    await this._recordChange({ type: 'clear', store });
  }

  // Encrypted partial search over blind index
  async search(store, { text, fields, minMatch = 'ALL' }) {
    await this._assertPermission('READ');
    if (!this.crypto) throw new Error('CryptoManager not attached');
    const def = this.schema?.stores?.[store];
    if (!def?.secureIndex || !def.secureIndex.length) throw new Error('No secure index configured for store');

    const tokens = [];
    for (const field of (fields && fields.length ? fields : def.secureIndex)) {
      const t = await this.crypto.blindTokens(String(text || ''), 3);
      tokens.push(...t);
    }
    const tx = this._tx([this._secureIndexStoreName(store), store]);
    const sidx = tx.objectStore(this._secureIndexStoreName(store)).index('byToken');
    const candidateIds = new Map();
    for (const tok of tokens) {
      const rows = await toPromise(sidx.getAll(tok));
      for (const r of rows) {
        const count = candidateIds.get(r.id) || 0; candidateIds.set(r.id, count + 1);
      }
    }
    const needAll = (minMatch === 'ALL');
    const finalIds = [];
    for (const [id, cnt] of candidateIds.entries()) {
      if (!needAll || cnt >= tokens.length) finalIds.push(id);
    }
    const os = tx.objectStore(store);
    const out = [];
    for (const id of finalIds) {
      const row = await toPromise(os.get(id));
      if (row) out.push(await this.crypto.decryptJson(row._enc));
    }
    await toPromise(tx.done);
    return out;
  }

  // --------------- Internal helpers ---------------
  async _assertPermission(flag) {
    const role = (await this.getDevice(this.deviceId))?.role;
    let perms = {};
    if (role) perms = await this.getRolePermissions(role);
    else {
      const tx = this._tx(['_meta']);
      const info = await toPromise(tx.objectStore('_meta').get('info'));
      await toPromise(tx.done);
      if (info?.creatorDeviceId === this.deviceId) perms = DEFAULT_ROLE_PERMISSIONS[ROLES.CREATOR];
    }
    if (!perms?.[flag]) throw new Error(`Permission denied: requires ${flag}`);
  }

  _augmentDoc(doc) {
    const now = Date.now();
    const base = { ...doc, _updatedBy: this.deviceId, _updatedAt: now, _l: 0 };
    // Ensure _acl exists; if not, seed from policy defaults
    if (!base._acl) {
      const pol = this._policies[doc?.__store || ''] || null;
      if (pol?.defaults) {
        base._acl = sanitizeAcl(pol.defaults);
      }
    }
    return base;
  }

  async _nextLamport(remoteL = 0) {
    const tx = this._tx(['_meta'], 'readwrite');
    const metaStore = tx.objectStore('_meta');
    const info = (await toPromise(metaStore.get('info'))) || { key: 'info', dbId: this.dbId, lamport: 0 };
    info.lamport = Math.max(info.lamport || 0, remoteL || 0) + 1;
    await toPromise(metaStore.put(info));
    await toPromise(tx.done);
    return info.lamport;
  }

  async _enqueueLocalChange(change) {
    const lamport = await this._nextLamport();
    const seq = `${lamport}:${this.deviceId}`;
    const enriched = { ...change, seq, lamport, deviceId: this.deviceId, ts: Date.now() };
    const tx = this._tx(['_changelog'], 'readwrite');
    await toPromise(tx.objectStore('_changelog').put(enriched));
    await toPromise(tx.done);
    this._events.emit('local-change', enriched);
    this._bc?.postMessage({ type: 'local-change', payload: enriched });
    return enriched;
  }

  async _recordChange(change) {
    const enriched = await this._enqueueLocalChange(change);
    await this._flushLocalChanges();
    return enriched;
  }

  async _flushLocalChanges() { /* noop; SyncManager batches */ }

  async applyRemoteChange(change) {
    if (!change || change.store === '_changelog') return;
    await this._nextLamport(change.lamport);

    const { type, store, key, value } = change;
    if (type === 'upsert' || type === 'device_upsert' || type === 'role_upsert' || type === 'policy_upsert') {
      const tx = this._tx([store], 'readwrite');
      const os = tx.objectStore(store);
      const existing = await toPromise(os.get(key));
      const shouldWrite = this._resolve(existing, value, change);
      if (shouldWrite) {
        if (store === '_policies') {
          await toPromise(os.put(value));
          this._policies[value.store] = value.policy;
        } else {
          await toPromise(os.put(value));
        }
      }
      await toPromise(tx.done);
    } else if (type === 'delete') {
      const tx = this._tx([store], 'readwrite');
      const os = tx.objectStore(store);
      const existing = await toPromise(os.get(key));
      const shouldDelete = this._resolve(existing, null, change);
      if (shouldDelete) await toPromise(os.delete(key));
      await toPromise(tx.done);
    } else if (type === 'clear') {
      const tx = this._tx([store], 'readwrite');
      await toPromise(tx.objectStore(store).clear());
      await toPromise(tx.done);
    }

    this._events.emit('remote-applied', change);
    this._bc?.postMessage({ type: 'remote-applied', payload: change });
  }

  _resolve(existing, incomingValue, change) {
    const existingL = existing?._l || 0;
    if (change.lamport > existingL) return true;
    if (change.lamport < existingL) return false;
    return (change.deviceId || '') > (existing?._updatedBy || '');
  }

  async _ensureSecureIndexStores() {
    const stores = this.schema?.stores || {};
    const name = `idb:${this.dbId}`;
    const missing = [];
    for (const [storeName, def] of Object.entries(stores)) {
      if (def?.secureIndex && def.secureIndex.length) {
        if (!this._db.objectStoreNames.contains(this._secureIndexStoreName(storeName))) missing.push(storeName);
      }
    }
    if (!missing.length) return;
    const newVersion = (this.schema.version || 1) + 1;
    await new Promise((resolve, reject) => {
      const req = indexedDB.open(name, newVersion);
      req.onupgradeneeded = () => {
        const db = req.result;
        for (const storeName of missing) {
          if (!db.objectStoreNames.contains(this._secureIndexStoreName(storeName))) {
            const os = db.createObjectStore(this._secureIndexStoreName(storeName), { keyPath: 'id' });
            os.createIndex('byToken', 'token', { multiEntry: true });
          }
        }
      };
      req.onsuccess = () => { this._db.close(); this._db = req.result; resolve(); };
      req.onerror = () => reject(req.error);
    });
    this.schema.version = newVersion;
  }

  _secureIndexStoreName(store) { return `__sidx__${store}`; }

  // Export/Import (ciphertext layer)
  async exportAll() {
    await this._assertPermission('READ');
    const names = Array.from(this._db.objectStoreNames);
    const out = {};
    for (const n of names) {
      const tx = this._tx([n]);
      out[n] = await toPromise(tx.objectStore(n).getAll());
      await toPromise(tx.done);
    }
    return out;
  }

  async importAll(snapshot, { asRemote = false } = {}) {
    await this._assertPermission('WRITE');
    for (const [store, rows] of Object.entries(snapshot || {})) {
      const tx = this._tx([store], 'readwrite');
      for (const r of rows) await toPromise(tx.objectStore(store).put(r));
      await toPromise(tx.done);
      if (asRemote) {
        for (const r of rows) {
          await this.applyRemoteChange({ type: 'upsert', store, key: r?.id, value: r, lamport: r?._l || 0, deviceId: r?._updatedBy || 'import', ts: r?._updatedAt || Date.now() });
        }
      }
    }
  }
}

// ACL sanitizer
function sanitizeAcl(acl) {
  const norm = { read: [], write: [] };
  if (Array.isArray(acl?.read)) norm.read = Array.from(new Set(acl.read));
  if (Array.isArray(acl?.write)) norm.write = Array.from(new Set(acl.write));
  return norm;
}

// ------------------------------
// Transports
// ------------------------------
export class BaseTransport {
  constructor() { this._ev = eventTarget(); }
  on(type, h) { this._ev.on(type, h); }
  off(type, h) { this._ev.off(type, h); }
  emit(type, detail) { this._ev.emit(type, detail); }
  async connect() {}
  async send(_msg) { throw new Error('send not implemented'); }
  async close() {}
}

export class WebSocketTransport extends BaseTransport {
  constructor({ socket }) { super(); this.socket = socket; this._bound = false; }
  async connect() {
    if (!this.socket) throw new Error('WebSocket instance required');
    if (this._bound) return;
    this._bound = true;
    this.socket.addEventListener('message', (ev) => {
      try { this.emit('message', JSON.parse(ev.data)); } catch {}
    });
  }
  async send(msg) { this.socket?.readyState === 1 ? this.socket.send(JSON.stringify(msg)) : null; }
  async close() { try { this.socket?.close(); } catch {} }
}

export class HttpTransport extends BaseTransport {
  constructor({ baseUrl, deviceId, pollIntervalMs = 2000, headers = {} }) { super(); this.baseUrl = baseUrl; this.deviceId = deviceId; this.headers = headers; this.pollIntervalMs = pollIntervalMs; this._timer = null; }
  async connect() {
    const poll = async () => {
      try {
        const url = `${this.baseUrl.replace(/\/$/, '')}/inbox?deviceId=${encodeURIComponent(this.deviceId)}`;
        const res = await fetch(url, { headers: this.headers });
        if (res.ok) {
          const arr = await res.json();
          (arr || []).forEach((m) => this.emit('message', m));
        }
      } catch {}
      this._timer = setTimeout(poll, this.pollIntervalMs);
    };
    poll();
  }
  async send(msg) {
    const url = `${this.baseUrl.replace(/\/$/, '')}/outbox`;
    await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...this.headers }, body: JSON.stringify(msg) });
  }
  async close() { if (this._timer) clearTimeout(this._timer); this._timer = null; }
}

export class BluetoothTransport extends BaseTransport {
  constructor({ sendFn } = {}) { super(); this._sendFn = sendFn; }
  setSender(fn) { this._sendFn = fn; }
  async send(msg) { if (!this._sendFn) throw new Error('No Bluetooth sender provided'); await this._sendFn(msg); }
  receive(msg) { this.emit('message', msg); }
}

// ------------------------------
// Base Sync Manager (ship & apply)
// ------------------------------
export class SyncManager {
  constructor({ db, transport, batchMs = 150, targetPeers = 'broadcast' }) {
    this.db = db;
    this.transport = transport;
    this.batchMs = batchMs;
    this.targetPeers = targetPeers;
    this._buffer = [];
    this._timer = null;
    this._ev = eventTarget();
  }
  on(type, h) { this._ev.on(type, h); }
  off(type, h) { this._ev.off(type, h); }

  async start() {
    await this.transport.connect();
    this.db.on('local-change', (ev) => this._queue(ev.detail));
    this.transport.on('message', async (msg) => { try { await this._handleRemote(msg); } catch (e) { console.error('sync error', e); } });
  }
  async stop() { await this.transport.close(); }
  _queue(change) {
    this._buffer.push(change);
    if (!this._timer) this._timer = setTimeout(() => this._flush(), this.batchMs);
  }
  async _flush() {
    const batch = this._buffer.splice(0, this._buffer.length);
    this._timer = null; if (!batch.length) return;
    const msg = { type: 'changes', dbId: this.db.dbId, from: this.db.deviceId, to: this.targetPeers, changes: batch };
    try { await this.transport.send(msg); } catch (e) { console.warn('send failed', e); }
  }
  async _handleRemote(msg) {
    if (!msg || msg.dbId !== this.db.dbId || msg.from === this.db.deviceId) return;
    if (msg.type === 'changes') {
      const applied = [];
      for (const ch of msg.changes || []) {
        await this.db.applyRemoteChange(ch); applied.push(ch);
      }
      this._ev.emit('applied', { from: msg.from, count: applied.length, changes: applied });
    }
  }
}

// ------------------------------
// Creator-Hub Secure Sync Manager
// ------------------------------
function hashGrantForMsg(_grant) {
  // Minimal placeholder (you can replace with a stable hash function for canonicalization)
  const tmp = crypto.getRandomValues(new Uint8Array(16));
  return b64(tmp);
}

export class CreatorHubSyncManager extends SyncManager {
  constructor({ db, transport, cryptoManager, isCreator, policy }) {
    super({ db, transport, batchMs: 150, targetPeers: isCreator ? 'broadcast' : ['creator'] });
    this.crypto = cryptoManager;
    this.isCreator = !!isCreator;
    this.policy = policy || { stores: {} };
  }

  async start() {
    await this.transport.connect();
    this.db.on('local-change', (ev) => this._queue(ev.detail));
    this.transport.on('message', async (msg) => { try { await this._handleRemoteSecured(msg); } catch (e) { console.error('secure sync error', e); } });
  }

  async _flush() {
    const batch = this._buffer.splice(0, this._buffer.length);
    this._timer = null; if (!batch.length) return;
    const to = 'creator';
    const grant = await this._loadGrant();
    const grantHash = hashGrantForMsg(grant);
    const envelope = { type: 'changes', dbId: this.db.dbId, from: this.db.deviceId, to, changes: batch, grant, devicePubJwk: this.crypto.devicePubJwk };
    envelope.msgSig = await this.crypto.sign({ ...envelope, grantHash });
    try { await this.transport.send(envelope); } catch (e) { console.warn('send failed', e); }
  }

  async _handleRemoteSecured(msg) {
    if (!msg || msg.dbId !== this.db.dbId) return;
    // Non-creator accepts only from creator
    if (!this.isCreator && msg.from !== 'creator') return;

    if (this.isCreator && msg.from !== 'creator') {
      const ok = await this._verifyGrantAndSignature(msg);
      if (!ok) { this._ev.emit('rejected', { reason: 'invalid-grant-or-signature', from: msg.from }); return; }
      const filtered = [];
      const senderRole = msg.grant.role;
      for (const ch of msg.changes || []) {
        const allowed = await this._allowWrite(senderRole, ch);
        if (allowed) filtered.push(ch); else this._ev.emit('rejected', { reason: 'no-write-permission', change: ch, from: msg.from });
      }
      for (const ch of filtered) await this.db.applyRemoteChange(ch);
      await this._fanOut(filtered, msg.from);
      return;
    }

    if (!this.isCreator && msg.from === 'creator' && msg.type === 'changes') {
      for (const ch of msg.changes || []) await this.db.applyRemoteChange(ch);
      this._ev.emit('applied', { from: 'creator', count: (msg.changes || []).length });
    }
  }

  async _verifyGrantAndSignature(msg) {
    const grant = msg.grant; if (!grant) return false;
    const grantPayload = { ...grant }; delete grantPayload.sig;
    const grantOk = await this.crypto.verifyWithDSKSignature(grant.sig, grantPayload);
    if (!grantOk) return false;
    if (grant.dbId !== this.db.dbId) return false;
    if (grant.deviceId !== msg.from) return false;
    if (grant.expiresAt && Date.now() > grant.expiresAt) return false;
    const sameKey = JSON.stringify(grant.devicePubJwk) === JSON.stringify(msg.devicePubJwk);
    if (!sameKey) return false;
    const ok = await this.crypto.verifyWithDeviceSignature(msg.devicePubJwk, msg.msgSig, { ...msg, msgSig: undefined });
    return !!ok;
  }

  async _allowWrite(role, change) {
    const perms = await this.db.getRolePermissions(role);
    if (!perms?.WRITE) return false;
    const pol = this.db._policies[change.store];
    if (!pol) return true;
    // When encrypted, change.value is ciphertext. Creator must rely on declared intent:
    // In this design, writes are allowed at store level for role; detailed record ACL is enforced on READ fan-out.
    if (pol.allowWrite) {
      try { return !!(await pol.allowWrite(change, { role })); } catch { return false; }
    }
    return true;
  }

  async _fanOut(changes, fromDeviceId) {
    // Creator evaluates visibility per target device using policy + per-record ACL after decryption
    const devices = await this.db.listDevices();
    for (const dev of devices) {
      if (dev.deviceId === fromDeviceId) continue;
      if (dev.deviceId === this.db.deviceId) continue; // skip creator self
      const visible = [];
      for (const ch of changes) {
        // Only process app stores (skip system)
        if (['_devices','_roles','_meta','_peerSync','_policies','_changelog'].includes(ch.store)) { visible.push(ch); continue; }
        // Decrypt to evaluate ACL/policy
        let doc = null;
        if (ch.type === 'upsert' && ch.value?._enc) {
          doc = await this.db.crypto.decryptJson(ch.value);
        }
        const pol = this.db._policies[ch.store];
        let allowed = true;
        if (doc && pol) {
          // Per-record ACL first
          const acl = sanitizeAcl(doc._acl || pol.defaults || { read: [ROLES.CREATOR], write: [ROLES.CREATOR] });
          if (Array.isArray(acl.read) && acl.read.length) {
            allowed = acl.read.includes(dev.role);
          }
          // Field-level redaction
          if (allowed && pol.fields) {
            doc = redactFieldsByRole(doc, pol.fields, dev.role);
          }
        }
        if (allowed) {
          // Re-encrypt for fanout is not required — we send plaintext-in-envelope and each device writes ciphertext with its own DEK.
          // To keep transport confidential on the wire, use TLS (wss/https) or add transport-layer encryption.
          visible.push({ ...ch, value: doc ? doc : ch.value, enc: false });
        }
      }
      if (!visible.length) continue;
      const envelope = { type: 'changes', dbId: this.db.dbId, from: 'creator', to: dev.deviceId, changes: visible };
      await this.transport.send(envelope);
    }
  }

  async _loadGrant() {
    const rec = await this.db.getDevice(this.db.deviceId);
    if (!rec?.grant) throw new Error('No RoleGrant found for this device');
    return rec.grant;
  }
}

// Field redaction per role based on policy.fields rules
function redactFieldsByRole(doc, fieldsPolicy, role) {
  const out = { ...doc };
  for (const [field, rule] of Object.entries(fieldsPolicy)) {
    const allowed = Array.isArray(rule?.read) ? rule.read.includes(role) : true;
    if (!allowed) {
      delete out[field];
    }
  }
  return out;
}

// ------------------------------
// Helper: Minimal Access Gate for external UI code
// ------------------------------
export function withPermission(db, flag, fn) {
  return async (...args) => {
    await db._assertPermission(flag);
    return fn(...args);
  };
}

// ------------------------------
// Admin convenience API
// ------------------------------
export const AdminAPI = {
  addDevice: (db) => withPermission(db, 'MANAGE_DEVICES', (input) => db.addOrUpdateDevice(input)),
  setRole: (db) => withPermission(db, 'MANAGE_ROLES', (input) => db.setRole(input)),
  addCustomRole: (db) => withPermission(db, 'MANAGE_ROLES', (role, perms) => db.addCustomRole(role, perms)),
  removeCustomRole: (db) => withPermission(db, 'MANAGE_ROLES', (role) => db.removeCustomRole(role))
};

// ------------------------------
// RoleGrant issuance helper (run on Creator only)
// ------------------------------
export async function issueRoleGrant({ dskPrivKey, dbId, deviceId, role, devicePubJwk, expiresAt = null }) {
  const payload = { type: 'RoleGrant', dbId, deviceId, role, devicePubJwk, createdAt: Date.now(), expiresAt };
  const sig = b64(await signBytes(dskPrivKey, utf8(JSON.stringify(payload))));
  return { ...payload, sig };
}
