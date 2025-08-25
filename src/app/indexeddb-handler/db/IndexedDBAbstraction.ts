import { DEFAULT_ROLE_PERMISSIONS, ROLES } from '../constants';
import { RolePermissions, Schema } from '../types';
import { eventTarget, toPromise, uid } from '../utils/basics';
import { CryptoManager } from '../crypto/CryptoManager';

type TxWithDone = IDBTransaction & { done: Promise<void> };

export class IndexedDBAbstraction {
    dbId: string;
    deviceId: string;
    schema: Schema;
    rolePermissions: Record<string, RolePermissions>;
    private _db: IDBDatabase | null = null;
    private _events = eventTarget();
    private _bc: BroadcastChannel | null = null;
    crypto: CryptoManager | null = null;
    _policies: Record<string, any> = {};

    constructor({ dbId, deviceId, schema, rolePermissions = DEFAULT_ROLE_PERMISSIONS }:
        { dbId: string; deviceId: string; schema?: Schema; rolePermissions?: Record<string, RolePermissions> }) {
        this.dbId = dbId;
        this.deviceId = deviceId;
        this.schema = schema || { version: 1, stores: {} };
        this.rolePermissions = rolePermissions;
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

                // system stores
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

                        // normal indexes
                        (def?.indexes || []).forEach((idx) => os.createIndex(idx.name, idx.keyPath, idx.options || {}));

                        // secure-index: add multiEntry index for each field
                        (def?.secureIndex || []).forEach((field) => {
                            const idxName = `sidx_${field}`;
                            os.createIndex(idxName, field, { unique: false, multiEntry: true });
                        });

                    } else if ((ev.oldVersion || 0) < version) {
                        const os = (req.transaction as IDBTransaction).objectStore(storeName);

                        (def?.indexes || []).forEach((idx) => {
                            if (!os.indexNames.contains(idx.name)) os.createIndex(idx.name, idx.keyPath, idx.options || {});
                        });

                        (def?.secureIndex || []).forEach((field) => {
                            const idxName = `sidx_${field}`;
                            if (!os.indexNames.contains(idxName)) os.createIndex(idxName, field, { unique: false, multiEntry: true });
                        });
                    }
                }
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });

        // seed meta + roles
        const tx = this._tx(['_meta', '_roles'], 'readwrite');
        const metaStore = tx.objectStore('_meta');
        const rolesStore = tx.objectStore('_roles');
        const info = (await toPromise(metaStore.get('info'))) || { key: 'info', dbId: this.dbId, createdAt: Date.now(), lamport: 0, creatorDeviceId: this.deviceId };
        await toPromise(metaStore.put(info));
        for (const role of Object.keys(this.rolePermissions)) {
            const existing = await toPromise(rolesStore.get(role));
            if (!existing) await toPromise(rolesStore.put({ role, permissions: this.rolePermissions[role] }));
        }
        await (tx as TxWithDone).done.catch(() => { });

        try {
            this._bc = new BroadcastChannel(`idb-sync:${this.dbId}`);
            this._bc.onmessage = (ev) => { if ((ev?.data as any)?.type) this._events.emit((ev.data as any).type, (ev.data as any).payload); };
        } catch { }

        // Load policies into memory
        this._policies = await this._loadPolicies();
        return this;
    }

    private _tx(storeNames: string[], mode: IDBTransactionMode = 'readonly'): TxWithDone {
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

    async addOrUpdateDevice({ deviceId, role, grant }: { deviceId: string; role?: string; grant?: any }) {
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
        const all = await toPromise(tx.objectStore('_devices').getAll());
        await tx.done;
        return all;
    }

    async listRoles() {
        const tx = this._tx(['_roles']);
        const all = await toPromise(tx.objectStore('_roles').getAll());
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
        const me = await this.getDevice(this.deviceId);
        if (me?.role !== ROLES.CREATOR) throw new Error('Only creator can add/remove roles');
        const tx = this._tx(['_roles'], 'readwrite');
        await toPromise(tx.objectStore('_roles').put({ role, permissions }));
        await tx.done;
        await this._recordChange({ type: 'role_upsert', store: '_roles', key: role, value: { role, permissions } });
    }

    async removeCustomRole(role: string) {
        const me = await this.getDevice(this.deviceId);
        if (me?.role !== ROLES.CREATOR) throw new Error('Only creator can remove roles');
        if (([ROLES.CREATOR, ROLES.ADMIN, ROLES.EDITOR, ROLES.VIEWER, ROLES.SYNC_AGENT] as string[]).includes(role))
            throw new Error('Cannot remove built-in role');
        const tx = this._tx(['_roles'], 'readwrite');
        await toPromise(tx.objectStore('_roles').delete(role));
        await tx.done;
        await this._recordChange({ type: 'role_delete', store: '_roles', key: role });
    }

    async setPolicy(store: string, policy: any) {
        const me = await this.getDevice(this.deviceId);
        if (me?.role !== ROLES.CREATOR) throw new Error('Only creator can set policy');
        const tx = this._tx(['_policies'], 'readwrite');
        await toPromise(tx.objectStore('_policies').put({ store, policy }));
        await tx.done;
        this._policies[store] = policy;
        await this._recordChange({ type: 'policy_upsert', store: '_policies', key: store, value: { store, policy } });
    }

    private async _loadPolicies() {
        const tx = this._tx(['_policies']);
        const rows = await toPromise(tx.objectStore('_policies').getAll());
        await tx.done;
        const out: Record<string, any> = {};
        for (const r of rows) out[r.store] = r.policy;
        return out;
    }

    // ---------------- CRUD (encrypted payloads + blind index tokens in the same record) ----------------

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

    async getAll(store: string, needDecryption = true) {
        await this._assertPermission('READ');
        if (!this.crypto) throw new Error('CryptoManager not attached');
        const tx = this._tx([store]);
        const rows = await toPromise(tx.objectStore(store).getAll());
        await tx.done;
        if (!needDecryption) return rows;

        const out: any[] = [];
        for (const r of rows) out.push(await this.crypto.decryptJson(r._enc));
        return out;
    }

    async put(store: string, value: any, key?: string) {
        await this._assertPermission('WRITE');
        if (!this.crypto) throw new Error('CryptoManager not attached');
        const withMeta = this._augmentDoc(value);

        // build secure index tokens directly into record as arrays
        const def = this.schema?.stores?.[store];
        const withMetaCopy: any = JSON.parse(JSON.stringify(withMeta));
        if (def?.secureIndex?.length) {
            for (const field of def.secureIndex) {
                const val = (withMeta?.[field] ?? '') + '';
                const t = await this.crypto.blindTokens(val, 3);
                withMetaCopy[field] = t; // this matches the multiEntry index
            }
        }

        const enc = await this.crypto.encryptJson(withMeta);
        const idKey = key ?? withMeta?.id ?? uid('key');

        const tx = this._tx([store], 'readwrite');
        await toPromise(tx.objectStore(store).put({ id: idKey, _enc: enc, ...withMetaCopy }));
        await tx.done;

        await this._recordChange({ type: 'upsert', store, key: idKey, value: enc, enc: true });
        return idKey;
    }

    async bulkPut(store: string, values: any[]) {
        await this._assertPermission('WRITE');
        if (!this.crypto) throw new Error('CryptoManager not attached');
        const def = this.schema?.stores?.[store];

        const tx = this._tx([store], 'readwrite');
        const keys: string[] = [];
        for (const v of values) {
            const withMeta = this._augmentDoc(v);
            const enc = await this.crypto.encryptJson(withMeta);
            const idKey = withMeta?.id ?? uid('key');

            const withMetaCopy: any = JSON.parse(JSON.stringify(withMeta));
            if (def?.secureIndex?.length) {
                for (const f of def.secureIndex) {
                    const t = await this.crypto.blindTokens(String(withMeta?.[f] ?? ''), 3);
                    withMetaCopy[f] = t;
                }
            }
            await toPromise(tx.objectStore(store).put({ id: idKey, _enc: enc, ...withMetaCopy }));
            keys.push(idKey);
            await this._enqueueLocalChange({ type: 'upsert', store, key: idKey, value: enc, enc: true });
        }
        await tx.done;
        await this._flushLocalChanges();
        return keys;
    }

    async delete(store: string, key: string) {
        await this._assertPermission('DELETE');
        const tx = this._tx([store], 'readwrite');
        await toPromise(tx.objectStore(store).delete(key));
        await tx.done;
        await this._recordChange({ type: 'delete', store, key });
    }

    async clear(store: string) {
        await this._assertPermission('DELETE');
        const tx = this._tx([store], 'readwrite');
        await toPromise(tx.objectStore(store).clear());
        await tx.done;
        await this._recordChange({ type: 'clear', store });
    }

    // Encrypted partial search over blind index
    async search(store: string, { text, fields, minMatch = 'ALL' }: { text: string; fields?: string[]; minMatch?: 'ALL' | 'ANY' }) {
        await this._assertPermission('READ');
        if (!this.crypto) throw new Error('CryptoManager not attached');
        const def = this.schema?.stores?.[store];
        if (!def?.secureIndex?.length) throw new Error('No secure index configured for store');

        const activeFields = (fields && fields.length) ? fields : def.secureIndex;
        // build tokens for the query string
        const queryTokens = await this.crypto.blindTokens(String(text || ''), 3);
        if (!queryTokens.length) return [];

        const tx = this._tx([store]);
        const os = tx.objectStore(store);

        // Collect candidate ids: use multiEntry index for each field and each token
        const candidateCounts = new Map<string, number>();
        for (const field of activeFields) {
            const idxName = `sidx_${field}`;
            if (!os.indexNames.contains(idxName)) continue;
            const idx = os.index(idxName);

            for (const tok of queryTokens) {
                const rows = await toPromise(idx.getAll(IDBKeyRange.only(tok)));
                for (const r of rows) {
                    const count = candidateCounts.get(r.id) || 0;
                    candidateCounts.set(r.id, count + 1);
                }
            }
        }

        const needAll = (minMatch === 'ALL');
        const requiredCount = needAll ? queryTokens.length * activeFields.length : 1;

        const finalIds: string[] = [];
        for (const [id, cnt] of candidateCounts.entries()) {
            if (cnt >= requiredCount) finalIds.push(id);
        }

        const out: any[] = [];
        for (const id of finalIds) {
            const row = await toPromise(os.get(id));
            if (row) out.push(await this.crypto.decryptJson(row._enc));
        }
        await tx.done;
        return out;
    }

    // ------------------- internal helpers -------------------

    private async _assertPermission(flag: keyof RolePermissions | 'READ' | 'WRITE' | 'DELETE' | 'MANAGE_ROLES' | 'MANAGE_DEVICES' | 'MANAGE_SCHEMA') {
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

    private _augmentDoc(doc: any) {
        const now = Date.now();
        const base = { ...doc, _updatedBy: this.deviceId, _updatedAt: now, _l: 0 };
        if (!base._acl) {
            const pol = this._policies[doc?.__store || ''] || null;
            if (pol?.defaults) base._acl = sanitizeAcl(pol.defaults);
        }
        return base;
    }

    private async _nextLamport(remoteL = 0) {
        const tx = this._tx(['_meta'], 'readwrite');
        const metaStore = tx.objectStore('_meta');
        const info = (await toPromise(metaStore.get('info'))) || { key: 'info', dbId: this.dbId, lamport: 0 };
        info.lamport = Math.max(info.lamport || 0, remoteL || 0) + 1;
        await toPromise(metaStore.put(info));
        await tx.done;
        return info.lamport;
    }

    private async _enqueueLocalChange(change: any) {
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

    private async _recordChange(change: any) {
        const enriched = await this._enqueueLocalChange(change);
        await this._flushLocalChanges();
        return enriched;
    }

    // Batched by SyncManager (no-op locally)
    protected async _flushLocalChanges() { }

    async applyRemoteChange(_change: any) {
        // Kept for future sync integration; no-op for local-only flow
        return;
    }

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

    async importAll(snapshot: Record<string, any[]>) {
        await this._assertPermission('WRITE');
        for (const [store, rows] of Object.entries(snapshot || {})) {
            const tx = this._tx([store], 'readwrite');
            for (const r of rows) await toPromise(tx.objectStore(store).put(r));
            await tx.done;
        }
    }
}

// Local import for sanitizer to avoid a circular chunk at runtime
function sanitizeAcl(acl: any) {
    const norm: { read: string[]; write: string[] } = { read: [], write: [] };
    if (Array.isArray(acl?.read)) norm.read = Array.from(new Set(acl.read));
    if (Array.isArray(acl?.write)) norm.write = Array.from(new Set(acl.write));
    return norm;
}
