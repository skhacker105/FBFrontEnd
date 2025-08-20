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

/* indexeddb-secure-sync.full.ts
   TypeScript 5.4.2 conversion of the provided JS module
*/

type Uint8ArrayOrArrayBuffer = Uint8Array | ArrayBuffer;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function uid(prefix = 'id') {
  return `${prefix}_${Math.random().toString(36).slice(2)}_${Date.now()}`;
}

function toPromise<T = any>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function eventTarget() {
  const et = new EventTarget();
  return {
    target: et,
    on: (type: string, handler: EventListenerOrEventListenerObject, opts?: boolean | AddEventListenerOptions) =>
      et.addEventListener(type, handler, opts),
    off: (type: string, handler: EventListenerOrEventListenerObject, opts?: boolean | EventListenerOptions) =>
      et.removeEventListener(type, handler, opts),
    emit: (type: string, detail?: any) => et.dispatchEvent(new CustomEvent(type, { detail }))
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
} as const);

export type Role = typeof ROLES[keyof typeof ROLES];

export type RolePermissions = {
  READ?: boolean;
  WRITE?: boolean;
  DELETE?: boolean;
  MANAGE_ROLES?: boolean;
  MANAGE_DEVICES?: boolean;
  MANAGE_SCHEMA?: boolean;
};

export const DEFAULT_ROLE_PERMISSIONS: Record<string, RolePermissions> = Object.freeze({
  [ROLES.CREATOR]: { READ: true, WRITE: true, DELETE: true, MANAGE_ROLES: true, MANAGE_DEVICES: true, MANAGE_SCHEMA: true },
  [ROLES.ADMIN]: { READ: true, WRITE: true, DELETE: true, MANAGE_ROLES: true, MANAGE_DEVICES: true, MANAGE_SCHEMA: false },
  [ROLES.EDITOR]: { READ: true, WRITE: true, DELETE: false, MANAGE_ROLES: false, MANAGE_DEVICES: false, MANAGE_SCHEMA: false },
  [ROLES.VIEWER]: { READ: true, WRITE: false, DELETE: false, MANAGE_ROLES: false, MANAGE_DEVICES: false, MANAGE_SCHEMA: false },
  [ROLES.SYNC_AGENT]: { READ: true, WRITE: true, DELETE: false, MANAGE_ROLES: false, MANAGE_DEVICES: false, MANAGE_SCHEMA: false }
});

// ------------------------------
// WebCrypto helpers
// ------------------------------
function utf8(str: string) { return new TextEncoder().encode(str); }
function b64(bytes: Uint8Array) { return btoa(String.fromCharCode(...bytes)); }
function fromB64(s: string) { return new Uint8Array([...atob(s)].map(c => c.charCodeAt(0))); }

async function importAesKey(raw: Uint8Array) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function exportRawKey(key: CryptoKey) { return new Uint8Array(await crypto.subtle.exportKey('raw', key)); }
async function genAesKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function genSigningKeyPair() {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}
async function signBytes(privKey: CryptoKey, bytes: Uint8Array) {
  return new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privKey, bytes));
}
async function verifyBytes(pubKey: CryptoKey, sig: Uint8Array, bytes: Uint8Array) {
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, sig, bytes);
}
async function importPubJwk(jwk: JsonWebKey) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
}
async function importPrivJwk(jwk: JsonWebKey) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
}
async function hmacKeyFromRaw(raw: Uint8Array) {
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}
async function hmacDigest(key: CryptoKey, bytes: Uint8Array) {
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, bytes));
}

export async function bootstrapSecrets(dbId: string, deviceId: string): Promise<SecretBundle> {
  // 1. Generate AES key for data encryption
  const aesKey = await genAesKey();
  const dekRaw = await exportRawKey(aesKey);

  // 2. Generate HMAC key for blind indexes
  const indexKey = await genAesKey(); // reuse AES generator, raw 32 bytes is fine
  const indexKeyRaw = await exportRawKey(indexKey);

  // 3. Generate device signing keypair (ECDSA P-256)
  const { publicKey, privateKey } = await genSigningKeyPair();
  const devicePubJwk = await crypto.subtle.exportKey("jwk", publicKey);
  const devicePrivJwk = await crypto.subtle.exportKey("jwk", privateKey);

  // 4. In creator device case: also generate DSK (signing keypair for grants)
  // For non-creator, this comes from creator later.
  // Example:
  // const { publicKey: dskPub, privateKey: dskPriv } = await genSigningKeyPair();
  // const dskPubJwk = await crypto.subtle.exportKey("jwk", dskPub);
  // const dskPrivJwk = await crypto.subtle.exportKey("jwk", dskPriv);

  // Save securely (NOT in IndexedDB if you care about tamper resistance)
  // e.g., localStorage + OS-level key store, or passcode-protected secure enclave

  return {
    dekRaw,
    indexKeyRaw,
    devicePrivJwk: devicePrivJwk as JsonWebKey,
    devicePubJwk: devicePubJwk as JsonWebKey,
    dskPubJwk: null // unless you’re on the creator and want to inject the creator’s pubkey here
  };
}

// n-grams for partial search
function ngrams(s: string, n = 3) {
  const out = new Set<string>();
  const str = (s || '').toLowerCase();
  if (!str) return out;
  if (str.length <= n) { out.add(str); return out; }
  for (let i = 0; i <= str.length - n; i++) out.add(str.slice(i, i + n));
  return out;
}

// ------------------------------
// Types used across module
// ------------------------------
export type SchemaStoreDef = {
  keyPath?: string;
  autoIncrement?: boolean;
  indexes?: { name: string; keyPath: string | string[]; options?: IDBIndexParameters }[];
  secureIndex?: string[]; // fields that are blind-indexed
};

export type Schema = {
  version: number;
  stores: Record<string, SchemaStoreDef>;
};

export type RoleGrant = {
  type: 'RoleGrant';
  dbId: string;
  deviceId: string;
  role: string;
  devicePubJwk: JsonWebKey;
  createdAt: number;
  expiresAt?: number | null;
  sig: string;
};

export type SecretBundle = {
  dekRaw: Uint8Array; // 32 bytes
  indexKeyRaw: Uint8Array; // 32 bytes
  devicePrivJwk: JsonWebKey;
  devicePubJwk: JsonWebKey;
  dskPubJwk?: JsonWebKey | null;
};

// ------------------------------
// CryptoManager: per-device encryption + blind index + signatures
// ------------------------------
export class CryptoManager {
  deviceId: string;
  dbId: string;
  loadSecrets: () => Promise<SecretBundle>;
  ready: Promise<void>;

  dek!: CryptoKey;
  indexKey!: CryptoKey;
  devicePub!: CryptoKey;
  devicePriv!: CryptoKey;
  dskPub: CryptoKey | null = null;
  devicePubJwk?: JsonWebKey;

  constructor({ deviceId, dbId, loadSecrets }: { deviceId: string; dbId: string; loadSecrets: () => Promise<SecretBundle> }) {
    this.deviceId = deviceId;
    this.dbId = dbId;
    this.loadSecrets = loadSecrets;
    this.ready = this._init();
  }

  private async _init() {
    const s = await this.loadSecrets();
    if (!s) throw new Error('Crypto secrets not provided. Provide per-device secrets from secure storage.');
    this.dek = await importAesKey(s.dekRaw);
    this.indexKey = await hmacKeyFromRaw(s.indexKeyRaw);
    this.devicePub = await importPubJwk(s.devicePubJwk);
    this.devicePriv = await importPrivJwk(s.devicePrivJwk);
    this.dskPub = s.dskPubJwk ? await importPubJwk(s.dskPubJwk) : null;
    this.devicePubJwk = s.devicePubJwk;
  }

  async encryptJson(obj: any) {
    await this.ready;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.dek, utf8(JSON.stringify(obj))));
    return { iv: b64(iv), ct: b64(ct) };
  }

  async decryptJson(payload: { iv: string; ct: string } | null) {
    await this.ready;
    if (!payload) return null;
    const iv = fromB64(payload.iv); const ct = fromB64(payload.ct);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, this.dek, ct.buffer));
    return JSON.parse(new TextDecoder().decode(pt));
  }

  async blindTokens(str: string, n = 3) {
    await this.ready;
    const toks = ngrams(str, n);
    const out: string[] = [];
    for (const t of toks) { out.push(b64(await hmacDigest(this.indexKey, utf8(t)))); }
    return out;
  }

  async sign(obj: any) {
    await this.ready;
    return b64(await signBytes(this.devicePriv, utf8(JSON.stringify(obj))));
  }

  async verifyWithDSKSignature(sigB64: string, obj: any) {
    if (!this.dskPub) return false;
    const sig = fromB64(sigB64);
    return !!(await verifyBytes(this.dskPub, sig, utf8(JSON.stringify(obj))));
  }

  async verifyWithDeviceSignature(pubJwk: JsonWebKey, sigB64: string, obj: any) {
    const pub = await importPubJwk(pubJwk);
    return !!(await verifyBytes(pub, fromB64(sigB64), utf8(JSON.stringify(obj))));
  }
}

// ------------------------------
// IndexedDB Abstraction (base)
// ------------------------------
type TxWithDone = IDBTransaction & { done: Promise<void> };

export class IndexedDBAbstraction {
  dbId: string;
  deviceId: string;
  schema: Schema;
  rolePermissions: Record<string, RolePermissions>;
  _db: IDBDatabase | null = null;
  _events: ReturnType<typeof eventTarget>;
  _bc: BroadcastChannel | null = null;
  crypto: CryptoManager | null = null;
  _policies: Record<string, any> = {};

  constructor({ dbId, deviceId, schema, rolePermissions = DEFAULT_ROLE_PERMISSIONS }: { dbId: string; deviceId: string; schema?: Schema; rolePermissions?: Record<string, RolePermissions> }) {
    this.dbId = dbId;
    this.deviceId = deviceId;
    this.schema = schema || { version: 1, stores: {} };
    this.rolePermissions = rolePermissions;
    this._events = eventTarget();
    this._bc = null;
    this.crypto = null;
    this._policies = {};
  }

  on(type: string, handler: EventListenerOrEventListenerObject, opts?: boolean | AddEventListenerOptions) { this._events.on(type, handler, opts); }
  off(type: string, handler: EventListenerOrEventListenerObject, opts?: boolean | EventListenerOptions) { this._events.off(type, handler, opts); }

  attachCrypto(cryptoManager: CryptoManager) { this.crypto = cryptoManager; return this; }

  async init() {
    const name = `idb:${this.dbId}`;
    const version = this.schema.version || 1;
    this._db = await new Promise<IDBDatabase>((resolve, reject) => {
      const req = indexedDB.open(name, version);
      req.onupgradeneeded = (ev) => {
        const db = req.result;
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
            
          } else if ((ev.oldVersion || 0) < version) {
            const os = (req.transaction as IDBTransaction).objectStore(storeName);
            (def?.indexes || []).forEach((idx) => {
              if (!os.indexNames.contains(idx.name)) os.createIndex(idx.name, idx.keyPath, idx.options || {});
            });
          }

        }
      };
      req.onsuccess = () => {
        resolve(req.result);
      }
      req.onerror = () => {
        console.log('error = ', req.error)
        reject(req.error);
      }
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
    try { await (tx as TxWithDone).done; } catch (err) { console.log('er = ',err) }

    // BroadcastChannel
    try {
      this._bc = new BroadcastChannel(`idb-sync:${this.dbId}`);
      this._bc.onmessage = (ev) => { if ((ev?.data as any)?.type) this._events.emit((ev.data as any).type, (ev.data as any).payload); };
    } catch (err) { console.log('er = ',err) }

    // Create secure index stores if needed
    // await this._ensureSecureIndexStores();

    // Load policies into memory
    this._policies = await this._loadPolicies();
    return this;
  }

  _tx(storeNames: string[], mode: IDBTransactionMode = 'readonly'): TxWithDone {
    if (!this._db) throw new Error('DB not initialized');
    const tx = this._db.transaction(storeNames, mode) as TxWithDone;
    tx.done = new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(tx.error);
      tx.onerror = () => reject(tx.error);
    });
    return tx;
  }

  async getRolePermissions(role: string) {
    const tx = this._tx(['_roles']);
    const r = await toPromise(tx.objectStore('_roles').get(role));
    await tx.done;
    return r?.permissions || {};
  }

  async currentRole() {
    const r = await this.getDevice(this.deviceId);
    return r?.role || ROLES.VIEWER;
  }

  async ensureDevice({ deviceId, role = ROLES.VIEWER }: { deviceId: string; role?: string }) {
    const existing = await this.getDevice(deviceId);
    if (existing) return existing;
    return this.addOrUpdateDevice({ deviceId, role });
  }

  async addOrUpdateDevice({ deviceId, role, grant }: { deviceId: string; role?: string; grant?: RoleGrant | null }) {
    await this._assertPermission('MANAGE_DEVICES');
    const tx = this._tx(['_devices'], 'readwrite');
    const record = { deviceId, role, addedAt: Date.now(), addedBy: this.deviceId, grant: grant || null };
    await toPromise(tx.objectStore('_devices').put(record));
    await tx.done;
    await this._recordChange({ type: 'device_upsert', store: '_devices', key: deviceId, value: record });
    return record;
  }

  async setRole({ deviceId, role }: { deviceId: string; role: string }) {
    await this._assertPermission('MANAGE_ROLES');
    const dev = await this.getDevice(deviceId);
    if (!dev) throw new Error('Device not found');
    dev.role = role;
    const tx = this._tx(['_devices'], 'readwrite');
    await toPromise(tx.objectStore('_devices').put(dev));
    await tx.done;
    await this._recordChange({ type: 'device_upsert', store: '_devices', key: deviceId, value: dev });
    return dev;
  }

  async listDevices() {
    const tx = this._tx(['_devices']);
    const store = tx.objectStore('_devices');
    const all = await toPromise(store.getAll());
    await tx.done;
    return all;
  }

  async getDevice(deviceId: string) {
    const tx = this._tx(['_devices']);
    const v = await toPromise(tx.objectStore('_devices').get(deviceId));
    await tx.done;
    return v || null;
  }

  async addCustomRole(role: string, permissions: RolePermissions) {
    // Only creator can add/remove roles
    const me = await this.getDevice(this.deviceId);
    if (me?.role !== ROLES.CREATOR) throw new Error('Only creator can add/remove roles');
    const tx = this._tx(['_roles'], 'readwrite');
    await toPromise(tx.objectStore('_roles').put({ role, permissions }));
    await tx.done;
    await this._recordChange({ type: 'role_upsert', store: '_roles', key: role, value: { role, permissions } });
  }

  async removeCustomRole(role: any) {
    const me = await this.getDevice(this.deviceId);
    if (me?.role !== ROLES.CREATOR) throw new Error('Only creator can remove roles');
    if ([ROLES.CREATOR, ROLES.ADMIN, ROLES.EDITOR, ROLES.VIEWER, ROLES.SYNC_AGENT].includes(role))
      throw new Error('Cannot remove built-in role');
    const tx = this._tx(['_roles'], 'readwrite');
    await toPromise(tx.objectStore('_roles').delete(role));
    await tx.done;
    await this._recordChange({ type: 'role_delete', store: '_roles', key: role });
  }

  async setPolicy(store: string, policy: any) {
    // creator-only
    const me = await this.getDevice(this.deviceId);
    if (me?.role !== ROLES.CREATOR) throw new Error('Only creator can set policy');
    const tx = this._tx(['_policies'], 'readwrite');
    await toPromise(tx.objectStore('_policies').put({ store, policy }));
    await tx.done;
    this._policies[store] = policy;
    await this._recordChange({ type: 'policy_upsert', store: '_policies', key: store, value: { store, policy } });
  }

  async _loadPolicies() {
    const tx = this._tx(['_policies']);
    const rows = await toPromise(tx.objectStore('_policies').getAll());
    await tx.done;
    const out: Record<string, any> = {};
    for (const r of rows) out[r.store] = r.policy;
    return out;
  }

  // ACL helpers
  async setRecordAcl(store: string, id: string, acl: any) {
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
  async get(store: string, key: string) {
    await this._assertPermission('READ');
    if (!this.crypto) throw new Error('CryptoManager not attached');
    const tx = this._tx([store]);
    const val = await toPromise(tx.objectStore(store).get(key));
    await tx.done;
    if (!val) return null;
    const dec = await this.crypto.decryptJson(val._enc);
    return dec ?? null;
  }

  async getAll(store: string) {
    await this._assertPermission('READ');
    if (!this.crypto) throw new Error('CryptoManager not attached');
    const tx = this._tx([store]);
    const rows = await toPromise(tx.objectStore(store).getAll());
    await tx.done;
    const out: any[] = [];
    for (const r of rows) out.push(await this.crypto.decryptJson(r._enc));
    return out;
  }

  async put(store: string, value: any, key?: string) {
    await this._assertPermission('WRITE');
    if (!this.crypto) throw new Error('CryptoManager not attached');
    const withMeta = this._augmentDoc(value);

    // secure index build
    const def = this.schema?.stores?.[store];
    // let tokens: string[] = [];
    let withMeta_copy = JSON.parse(JSON.stringify(withMeta));
    if (def?.secureIndex && def.secureIndex.length) {
      for (const field of def.secureIndex) {
        const val = (withMeta?.[field] ?? '') + '';
        const t = await this.crypto.blindTokens(val, 3);
        // tokens = tokens.concat(t);
        withMeta_copy[field] = t;
      }
    }

    // encrypt payload
    const enc = await this.crypto.encryptJson(withMeta);
    const idKey = key ?? withMeta?.id ?? uid('key');

    const tx = this._tx([store], 'readwrite');
    await toPromise(tx.objectStore(store).put({ id: idKey, _enc: enc, ...withMeta_copy }));
    await tx.done;

    await this._recordChange({ type: 'upsert', store, key: idKey, value: enc, enc: true });
    return idKey;
  }

  async bulkPut(store: string, values: any[]) {
    await this._assertPermission('WRITE');
    if (!this.crypto) throw new Error('CryptoManager not attached');
    const tx = this._tx([store, this._secureIndexStoreName(store)], 'readwrite');
    const ks: string[] = [];
    for (const v of values) {
      const withMeta = this._augmentDoc(v);
      const enc = await this.crypto.encryptJson(withMeta);
      const idKey = withMeta?.id ?? uid('key');
      await toPromise(tx.objectStore(store).put({ id: idKey, _enc: enc }));
      // secure index
      const def = this.schema?.stores?.[store];
      if (def?.secureIndex) {
        let tokens: string[] = [];
        for (const f of def.secureIndex) {
          const t = await this.crypto.blindTokens(String(withMeta?.[f] ?? ''), 3);
          tokens = tokens.concat(t);
        }
        await toPromise(tx.objectStore(this._secureIndexStoreName(store)).put({ id: idKey, token: tokens }));
      }
      ks.push(idKey);
      await this._enqueueLocalChange({ type: 'upsert', store, key: idKey, value: enc, enc: true });
    }
    await tx.done;
    await this._flushLocalChanges();
    return ks;
  }

  async delete(store: string, key: string) {
    await this._assertPermission('DELETE');
    const tx = this._tx([store, this._secureIndexStoreName(store)], 'readwrite');
    await toPromise(tx.objectStore(store).delete(key));
    await toPromise(tx.objectStore(this._secureIndexStoreName(store)).delete(key));
    await tx.done;
    await this._recordChange({ type: 'delete', store, key });
  }

  async clear(store: string) {
    await this._assertPermission('DELETE');
    const tx = this._tx([store, this._secureIndexStoreName(store)], 'readwrite');
    await toPromise(tx.objectStore(store).clear());
    await toPromise(tx.objectStore(this._secureIndexStoreName(store)).clear());
    await tx.done;
    await this._recordChange({ type: 'clear', store });
  }

  // Encrypted partial search over blind index
  async search(store: string, { text, fields, minMatch = 'ALL' }: { text: string; fields?: string[]; minMatch?: 'ALL' | 'ANY' }) {
    await this._assertPermission('READ');
    if (!this.crypto) throw new Error('CryptoManager not attached');
    const def = this.schema?.stores?.[store];
    if (!def?.secureIndex || !def.secureIndex.length) throw new Error('No secure index configured for store');

    const tokens: string[] = [];
    for (const field of (fields && fields.length ? fields : def.secureIndex)) {
      const t = await this.crypto.blindTokens(String(text || ''), 3);
      tokens.push(...t);
    }
    const tx = this._tx([store]);
    const sidx = tx.objectStore(store).index('byTitle');
    const candidateIds = new Map<string, number>();
    for (const tok of tokens) {
      const rows = await toPromise(sidx.getAll(tok));
      for (const r of rows) {
        const count = candidateIds.get(r.id) || 0; candidateIds.set(r.id, count + 1);
      }
    }
    const needAll = (minMatch === 'ALL');
    const finalIds: string[] = [];
    for (const [id, cnt] of candidateIds.entries()) {
      if (!needAll || cnt >= tokens.length) finalIds.push(id);
    }
    const os = tx.objectStore(store);
    const out: any[] = [];
    for (const id of finalIds) {
      const row = await toPromise(os.get(id));
      if (row) out.push(await this.crypto.decryptJson(row._enc));
    }
    await tx.done;
    return out;
  }

  // --------------- Internal helpers ---------------
  async _assertPermission(flag: keyof RolePermissions | 'READ' | 'WRITE' | 'DELETE' | 'MANAGE_ROLES' | 'MANAGE_DEVICES' | 'MANAGE_SCHEMA') {
    const roleRec = (await this.getDevice(this.deviceId))?.role;
    let perms: RolePermissions = {};
    if (roleRec) perms = (await this.getRolePermissions(roleRec)) as RolePermissions;
    else {
      const tx = this._tx(['_meta']);
      const info = await toPromise(tx.objectStore('_meta').get('info'));
      await tx.done;
      if (info?.creatorDeviceId === this.deviceId) perms = DEFAULT_ROLE_PERMISSIONS[ROLES.CREATOR];
    }
    if (!perms?.[flag]) throw new Error(`Permission denied: requires ${flag}`);
  }

  _augmentDoc(doc: any) {
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
    await tx.done;
    return info.lamport;
  }

  async _enqueueLocalChange(change: any) {
    const lamport = await this._nextLamport();
    const seq = `${lamport}:${this.deviceId}`;
    const enriched = { ...change, seq, lamport, deviceId: this.deviceId, ts: Date.now() };
    const tx = this._tx(['_changelog'], 'readwrite');
    await toPromise(tx.objectStore('_changelog').put(enriched));
    await tx.done;
    this._events.emit('local-change', enriched);
    this._bc?.postMessage({ type: 'local-change', payload: enriched });
    return enriched;
  }

  async _recordChange(change: any) {
    const enriched = await this._enqueueLocalChange(change);
    await this._flushLocalChanges();
    return enriched;
  }

  async _flushLocalChanges() { /* noop; SyncManager batches */ }

  async applyRemoteChange(change: any) {
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
      await tx.done;
    } else if (type === 'delete') {
      const tx = this._tx([store], 'readwrite');
      const os = tx.objectStore(store);
      const existing = await toPromise(os.get(key));
      const shouldDelete = this._resolve(existing, null, change);
      if (shouldDelete) await toPromise(os.delete(key));
      await tx.done;
    } else if (type === 'clear') {
      const tx = this._tx([store], 'readwrite');
      await toPromise(tx.objectStore(store).clear());
      await tx.done;
    }

    this._events.emit('remote-applied', change);
    this._bc?.postMessage({ type: 'remote-applied', payload: change });
  }

  _resolve(existing: any, incomingValue: any, change: any) {
    const existingL = existing?._l || 0;
    if (change.lamport > existingL) return true;
    if (change.lamport < existingL) return false;
    return (change.deviceId || '') > (existing?._updatedBy || '');
  }

  _secureIndexStoreName(store: string) { return `__sidx__${store}`; }

  // Export/Import (ciphertext layer)
  async exportAll() {
    await this._assertPermission('READ');
    if (!this._db) throw new Error('DB not initialized');
    const names = Array.from(this._db.objectStoreNames);
    const out: Record<string, any[]> = {};
    for (const n of names) {
      const tx = this._tx([n]);
      out[n] = await toPromise(tx.objectStore(n).getAll());
      await tx.done;
    }
    return out;
  }

  async importAll(snapshot: Record<string, any[]>, { asRemote = false } = {}) {
    await this._assertPermission('WRITE');
    for (const [store, rows] of Object.entries(snapshot || {})) {
      const tx = this._tx([store], 'readwrite');
      for (const r of rows) await toPromise(tx.objectStore(store).put(r));
      await tx.done;
      if (asRemote) {
        for (const r of rows) {
          await this.applyRemoteChange({ type: 'upsert', store, key: r?.id, value: r, lamport: r?._l || 0, deviceId: r?._updatedBy || 'import', ts: r?._updatedAt || Date.now() });
        }
      }
    }
  }
}

// ACL sanitizer
function sanitizeAcl(acl: any) {
  const norm: { read: string[]; write: string[] } = { read: [], write: [] };
  if (Array.isArray(acl?.read)) norm.read = Array.from(new Set(acl.read));
  if (Array.isArray(acl?.write)) norm.write = Array.from(new Set(acl.write));
  return norm;
}

// ------------------------------
// Transports
// ------------------------------
export class BaseTransport {
  _ev = eventTarget();
  on(type: string, h: any) { this._ev.on(type, h); }
  off(type: string, h: any) { this._ev.off(type, h); }
  emit(type: string, detail?: any) { this._ev.emit(type, detail); }
  async connect() { }
  async send(_msg: any) { throw new Error('send not implemented'); }
  async close() { }
}

export class WebSocketTransport extends BaseTransport {
  socket: WebSocket | null;
  private _bound = false;
  constructor({ socket }: { socket: WebSocket | null }) { super(); this.socket = socket; }
  override async connect() {
    if (!this.socket) throw new Error('WebSocket instance required');
    if (this._bound) return;
    this._bound = true;
    this.socket.addEventListener('message', (ev) => {
      try { this.emit('message', JSON.parse((ev as MessageEvent).data)); } catch { }
    });
  }
  override async send(msg: any) { if (this.socket?.readyState === 1) this.socket.send(JSON.stringify(msg)); }
  override async close() { try { this.socket?.close(); } catch { } }
}

export class HttpTransport extends BaseTransport {
  baseUrl: string;
  deviceId: string;
  pollIntervalMs: number;
  headers: Record<string, string>;
  private _timer: any = null;
  constructor({ baseUrl, deviceId, pollIntervalMs = 2000, headers = {} }: { baseUrl: string; deviceId: string; pollIntervalMs?: number; headers?: Record<string, string> }) {
    super();
    this.baseUrl = baseUrl;
    this.deviceId = deviceId;
    this.headers = headers;
    this.pollIntervalMs = pollIntervalMs;
  }
  override async connect() {
    const poll = async () => {
      try {
        const url = `${this.baseUrl.replace(/\/$/, '')}/inbox?deviceId=${encodeURIComponent(this.deviceId)}`;
        const res = await fetch(url, { headers: this.headers });
        if (res.ok) {
          const arr = await res.json();
          (arr || []).forEach((m: any) => this.emit('message', m));
        }
      } catch { }
      this._timer = setTimeout(poll, this.pollIntervalMs);
    };
    poll();
  }
  override async send(msg: any) {
    const url = `${this.baseUrl.replace(/\/$/, '')}/outbox`;
    await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...this.headers }, body: JSON.stringify(msg) });
  }
  override async close() { if (this._timer) clearTimeout(this._timer); this._timer = null; }
}

export class BluetoothTransport extends BaseTransport {
  private _sendFn?: (msg: any) => Promise<void>;
  constructor({ sendFn } = {} as { sendFn?: (msg: any) => Promise<void> }) { super(); this._sendFn = sendFn; }
  setSender(fn: (msg: any) => Promise<void>) { this._sendFn = fn; }
  override async send(msg: any) { if (!this._sendFn) throw new Error('No Bluetooth sender provided'); await this._sendFn(msg); }
  receive(msg: any) { this.emit('message', msg); }
}

// ------------------------------
// Base Sync Manager (ship & apply)
// ------------------------------
export class SyncManager {
  db: IndexedDBAbstraction;
  transport: BaseTransport;
  batchMs: number;
  targetPeers: 'broadcast' | string | string[];
  _buffer: any[] = [];
  _timer: any = null;
  _ev = eventTarget();

  constructor({ db, transport, batchMs = 150, targetPeers = 'broadcast' }: { db: IndexedDBAbstraction; transport: BaseTransport; batchMs?: number; targetPeers?: 'broadcast' | string | string[] }) {
    this.db = db;
    this.transport = transport;
    this.batchMs = batchMs;
    this.targetPeers = targetPeers;
  }

  on(type: string, h: any) { this._ev.on(type, h); }
  off(type: string, h: any) { this._ev.off(type, h); }

  async start() {
    await this.transport.connect();
    this.db.on('local-change', (ev: Event) => this._queue((ev as CustomEvent).detail));
    this.transport.on('message', async (msg: any) => { try { await this._handleRemote(msg); } catch (e) { console.error('sync error', e); } });
  }
  async stop() { await this.transport.close(); }
  _queue(change: any) {
    this._buffer.push(change);
    if (!this._timer) this._timer = setTimeout(() => this._flush(), this.batchMs);
  }
  async _flush() {
    const batch = this._buffer.splice(0, this._buffer.length);
    this._timer = null; if (!batch.length) return;
    const msg = { type: 'changes', dbId: this.db.dbId, from: this.db.deviceId, to: this.targetPeers, changes: batch };
    try { await this.transport.send(msg); } catch (e) { console.warn('send failed', e); }
  }
  async _handleRemote(msg: any) {
    if (!msg || msg.dbId !== this.db.dbId || msg.from === this.db.deviceId) return;
    if (msg.type === 'changes') {
      const applied: any[] = [];
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
function hashGrantForMsg(_grant: RoleGrant) {
  // Minimal placeholder (you can replace with a stable hash function for canonicalization)
  const tmp = crypto.getRandomValues(new Uint8Array(16));
  return b64(tmp);
}

export class CreatorHubSyncManager extends SyncManager {
  crypto: CryptoManager;
  isCreator: boolean;
  policy: any;

  constructor({ db, transport, cryptoManager, isCreator, policy }: { db: IndexedDBAbstraction; transport: BaseTransport; cryptoManager: CryptoManager; isCreator?: boolean; policy?: any }) {
    super({ db, transport, batchMs: 150, targetPeers: isCreator ? 'broadcast' : ['creator'] });
    this.crypto = cryptoManager;
    this.isCreator = !!isCreator;
    this.policy = policy || { stores: {} };
  }

  override async start() {
    await this.transport.connect();
    this.db.on('local-change', (ev: Event) => this._queue((ev as CustomEvent).detail));
    this.transport.on('message', async (msg: any) => { try { await this._handleRemoteSecured(msg); } catch (e) { console.error('secure sync error', e); } });
  }

  override async _flush() {
    const batch = this._buffer.splice(0, this._buffer.length);
    this._timer = null; if (!batch.length) return;
    const to = 'creator';
    const grant = await this._loadGrant();
    const grantHash = hashGrantForMsg(grant);
    const envelope: any = { type: 'changes', dbId: this.db.dbId, from: this.db.deviceId, to, changes: batch, grant, devicePubJwk: this.crypto.devicePubJwk };
    envelope.msgSig = await this.crypto.sign({ ...envelope, grantHash });
    try { await this.transport.send(envelope); } catch (e) { console.warn('send failed', e); }
  }

  async _handleRemoteSecured(msg: any) {
    if (!msg || msg.dbId !== this.db.dbId) return;
    // Non-creator accepts only from creator
    if (!this.isCreator && msg.from !== 'creator') return;

    if (this.isCreator && msg.from !== 'creator') {
      const ok = await this._verifyGrantAndSignature(msg);
      if (!ok) { this._ev.emit('rejected', { reason: 'invalid-grant-or-signature', from: msg.from }); return; }
      const filtered: any[] = [];
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

  async _verifyGrantAndSignature(msg: any) {
    const grant: RoleGrant | undefined = msg.grant;
    if (!grant) return false;
    const grantPayload = { ...grant }; delete (grantPayload as any).sig;
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

  async _allowWrite(role: string, change: any) {
    const perms = await this.db.getRolePermissions(role);
    if (!perms?.WRITE) return false;
    const pol = this.db._policies[change.store];
    if (!pol) return true;
    // When encrypted, change.value is ciphertext. Creator must rely on declared intent:
    if (pol.allowWrite) {
      try { return !!(await pol.allowWrite(change, { role })); } catch { return false; }
    }
    return true;
  }

  // ------------------- Completed _fanOut with per-record ACL + field redaction -------------------
  async _fanOut(changes: any[], fromDeviceId: string) {
    // Creator evaluates visibility per target device using policy + per-record ACL after decryption
    const devices = await this.db.listDevices();
    for (const dev of devices) {
      if (dev.deviceId === fromDeviceId) continue;
      if (dev.deviceId === this.db.deviceId) continue; // skip creator self
      const visible: any[] = [];
      for (const ch of changes) {
        // Only process app stores (skip system)
        if (['_devices', '_roles', '_meta', '_peerSync', '_policies', '_changelog'].includes(ch.store)) {
          visible.push(ch);
          continue;
        }

        let doc: any = null;
        if (ch.type === 'upsert' && ch.value?._enc) {
          // ch.value is ciphertext envelope (iv+ct) — decrypt using creator's DEK
          try { doc = await this.db.crypto?.decryptJson(ch.value) ?? null; } catch { doc = null; }
        } else if (ch.type === 'upsert' && ch.value && ch.enc === false) {
          // value is plaintext (maybe from local creation on creator device)
          doc = ch.value;
        }

        const pol = this.db._policies[ch.store];
        let allowed = true;

        if (doc && pol) {
          // Per-record ACL first: doc._acl overrides store defaults
          const acl = sanitizeAcl(doc._acl || pol.defaults || { read: [ROLES.CREATOR], write: [ROLES.CREATOR] });
          if (Array.isArray(acl.read) && acl.read.length) {
            allowed = acl.read.includes(dev.role);
          }
          // Field-level redaction
          if (allowed && pol.fields && typeof pol.fields === 'object') {
            doc = redactFieldsByRole(doc, pol.fields, dev.role);
          }
        }

        if (allowed) {
          // As per design comment: send plaintext in-envelope; recipients will re-encrypt with their own DEK
          // Attach metadata so recipient can properly store/encrypt locally.
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
export function redactFieldsByRole(doc: any, fieldsPolicy: Record<string, any>, role: string) {
  const out = { ...doc };
  for (const [field, rule] of Object.entries(fieldsPolicy || {})) {
    // rule.read might be array of roles allowed to read this field. If absent, default allow.
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
export function withPermission(db: IndexedDBAbstraction, flag: keyof RolePermissions, fn: (...args: any[]) => any) {
  return async (...args: any[]) => {
    await db._assertPermission(flag);
    return fn(...args);
  };
}

// ------------------------------
// Admin convenience API
// ------------------------------
export const AdminAPI = {
  addDevice: (db: IndexedDBAbstraction) => withPermission(db, 'MANAGE_DEVICES', (input: any) => db.addOrUpdateDevice(input)),
  setRole: (db: IndexedDBAbstraction) => withPermission(db, 'MANAGE_ROLES', (input: any) => db.setRole(input)),
  addCustomRole: (db: IndexedDBAbstraction) => withPermission(db, 'MANAGE_ROLES', (role: string, perms: RolePermissions) => db.addCustomRole(role, perms)),
  removeCustomRole: (db: IndexedDBAbstraction) => withPermission(db, 'MANAGE_ROLES', (role: string) => db.removeCustomRole(role))
};

// ------------------------------
// RoleGrant issuance helper (run on Creator only)
// ------------------------------
export async function issueRoleGrant({ dskPrivKey, dbId, deviceId, role, devicePubJwk, expiresAt = null }: { dskPrivKey: CryptoKey; dbId: string; deviceId: string; role: string; devicePubJwk: JsonWebKey; expiresAt?: number | null }) {
  const payload = { type: 'RoleGrant', dbId, deviceId, role, devicePubJwk, createdAt: Date.now(), expiresAt };
  const sig = b64(await signBytes(dskPrivKey, utf8(JSON.stringify(payload))));
  return { ...payload, sig };
}
