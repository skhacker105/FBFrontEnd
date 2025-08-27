import { CreatorHubSyncManager, CryptoManager, DBContext, DBListEntry, IndexedDBAbstraction, ROLES, RoleGrant, SecretBundle, WebSocketTransport, bootstrapSecrets, fromB64, issueRoleGrant, toB64 } from "./";

export class MultiDBManager {
    private static LS_KEY_DBS = 'multiDBManager_dbs';
    private static LS_KEY_DEVICE = 'multiDBManager_deviceId';
    private static LS_KEY_SELECTEDDB = 'multiDBManager_selectedDB';

    private dbContexts = new Map<string, DBContext>();
    private deviceId: string | null = null;
    private selectedDbId: string | null = null;

    constructor() {
        this.deviceId = localStorage.getItem(MultiDBManager.LS_KEY_DEVICE);
        this.selectedDbId = localStorage.getItem(MultiDBManager.LS_KEY_SELECTEDDB);

        const list = this.getDBList();
        list.forEach(entry => {
            this.restoreFromLocalStorage(
                this.deviceId!,
                entry.dbId,
                entry.schema,
                entry.creatorDeviceId
            ).catch(e => console.warn('Restore failed for DB', entry.dbId, e));
        });
    }

    // ---------- Device ----------
    setDeviceId(deviceId: string) {
        this.deviceId = deviceId;
        localStorage.setItem(MultiDBManager.LS_KEY_DEVICE, deviceId);
    }

    getDeviceId(): string | null {
        return this.deviceId;
    }

    // ---------- Secrets ----------
    private secretsKey(dbId: string, deviceId: string) {
        return `secrets_${dbId}_${deviceId}`;
    }

    private saveSecrets(dbId: string, deviceId: string, bundle: SecretBundle) {
        const key = this.secretsKey(dbId, deviceId);
        localStorage.setItem(
            key,
            JSON.stringify({
                ...bundle,
                dekRaw: toB64(bundle.dekRaw),
                indexKeyRaw: toB64(bundle.indexKeyRaw)
            })
        );
    }

    private loadSecrets(dbId: string, deviceId: string): SecretBundle | null {
        const key = this.secretsKey(dbId, deviceId);
        const raw = localStorage.getItem(key);
        if (!raw) return null;
        try {
            const parsed = JSON.parse(raw);
            return {
                ...parsed,
                dekRaw: fromB64(parsed.dekRaw),
                indexKeyRaw: fromB64(parsed.indexKeyRaw)
            };
        } catch {
            return null;
        }
    }

    private reviveSecretBundle(raw: any): SecretBundle {
        return {
            ...raw,
            dekRaw: fromB64(raw.dekRaw),
            indexKeyRaw: fromB64(raw.indexKeyRaw),
            devicePubJwk: raw.devicePubJwk,   // stays as object
            devicePrivJwk: raw.devicePrivJwk, // stays as object
        };
    }

    // ---------- DB list ----------
    private getDBList(): DBListEntry[] {
        const raw = localStorage.getItem(MultiDBManager.LS_KEY_DBS);
        return raw ? JSON.parse(raw) : [];
    }

    private saveDBList(list: DBListEntry[]) {
        localStorage.setItem(MultiDBManager.LS_KEY_DBS, JSON.stringify(list));
    }

    private addDBToList(entry: DBListEntry) {
        const list = this.getDBList();
        if (!list.find(e => e.dbId === entry.dbId)) {
            list.push(entry);
            this.saveDBList(list);
        }
    }

    // ---------- Selected DB ----------
    selectDB(dbId: string) {
        this.selectedDbId = dbId;
        localStorage.setItem(MultiDBManager.LS_KEY_SELECTEDDB, dbId);
    }

    resetSelectedDB() {
        this.selectedDbId = null;
        localStorage.removeItem(MultiDBManager.LS_KEY_SELECTEDDB);
    }

    getSelectedDB(): DBContext | null {
        if (!this.selectedDbId) return null;
        return this.dbContexts.get(this.selectedDbId) ?? null;
    }

    // ---------- Restore ----------
    private async restoreFromLocalStorage(
        deviceId: string,
        dbId: string,
        schema: any,
        creatorDeviceId: string | null
    ): Promise<boolean> {
        const secrets = this.loadSecrets(dbId, deviceId);
        if (!secrets) return false;

        const db = new IndexedDBAbstraction({ dbId, deviceId, schema });
        await db.init();

        const cryptoMgr = new CryptoManager({ deviceId, dbId, loadSecrets: async () => secrets });
        db.attachCrypto(cryptoMgr);

        await db.ensureDevice({ deviceId, role: ROLES.VIEWER });
        const me = await db.getDevice(deviceId);
        const myRole = me?.role ?? ROLES.VIEWER;

        const sync = await this.startSync(db, cryptoMgr, deviceId, dbId, myRole === ROLES.CREATOR, creatorDeviceId);

        const ctx: DBContext = {
            dbId,
            deviceId,
            creatorDeviceId,
            role: myRole,
            schema,
            db,
            cryptoMgr,
            sync,
            secrets
        };

        this.dbContexts.set(dbId, ctx);
        return true;
    }

    // ---------- DB Creation / Join / Connection String ----------
    async createDatabaseAsCreator(dbId: string, schema: any): Promise<void> {
        if (!this.deviceId) throw new Error('No Device Id found.');
        const deviceId = this.deviceId!;

        const db = new IndexedDBAbstraction({ dbId, deviceId, schema });
        await db.init();

        let cryptoSecret =
            this.loadSecrets(dbId, deviceId) ?? (await bootstrapSecrets(dbId, deviceId, true));
        this.saveSecrets(dbId, deviceId, cryptoSecret);

        const cryptoMgr = new CryptoManager({
            deviceId,
            dbId,
            loadSecrets: async () => cryptoSecret
        });
        db.attachCrypto(cryptoMgr);

        await db.ensureDevice({ deviceId, role: ROLES.CREATOR });

        if (cryptoMgr.devicePubJwk) {
            const grant: RoleGrant = await issueRoleGrant({
                cryptoManager: cryptoMgr,
                dbId,
                deviceId,
                role: ROLES.CREATOR,
                devicePubJwk: cryptoMgr.devicePubJwk
            });
            await db.addOrUpdateDevice({ deviceId, role: ROLES.CREATOR, grant });
        }

        const sync = await this.startSync(db, cryptoMgr, deviceId, dbId, true, deviceId);

        const ctx: DBContext = {
            dbId,
            deviceId,
            creatorDeviceId: deviceId,
            role: ROLES.CREATOR,
            schema,
            db,
            cryptoMgr,
            sync,
            secrets: cryptoSecret
        };

        this.dbContexts.set(dbId, ctx);
        this.addDBToList({ dbId, schema, role: ROLES.CREATOR, creatorDeviceId: deviceId });
        this.selectDB(dbId);
    }

    async joinAsDeviceFromImport(importDB: string): Promise<void> {
        let parsed: any;
        try {
            parsed = JSON.parse(importDB);
        } catch (err) {
            throw new Error(`Invalid connection string: ${err}`);
        }

        const {
            deviceId,
            dbId,
            role,
            schema,
            secret,
            creatorDeviceId
        } = parsed;

        if (!dbId || !role || !schema || !secret) {
            throw new Error('Connection string missing required fields');
        }

        // Important: local deviceId always comes from this.deviceId, not the string
        const revivedSecret = this.reviveSecretBundle(secret);

        await this.joinAsDevice(dbId, role, revivedSecret, schema, creatorDeviceId);
    }


    private async joinAsDevice(
        dbId: string,
        role: string,
        cryptoSecret: SecretBundle,
        schema: any,
        creatorDeviceId: string
    ): Promise<void> {
        if (!this.deviceId) throw new Error('No Device Id found.');
        const deviceId = this.deviceId!;

        this.saveSecrets(dbId, deviceId, cryptoSecret);

        const db = new IndexedDBAbstraction({ dbId, deviceId, schema });
        await db.init();

        const cryptoMgr = new CryptoManager({
            deviceId,
            dbId,
            loadSecrets: async () => cryptoSecret
        });
        db.attachCrypto(cryptoMgr);

        await db.ensureDevice({ deviceId, role });

        const sync = await this.startSync(db, cryptoMgr, deviceId, dbId, false, creatorDeviceId);

        const ctx: DBContext = {
            dbId,
            deviceId,
            creatorDeviceId,
            role,
            schema,
            db,
            cryptoMgr,
            sync,
            secrets: cryptoSecret
        };

        this.dbContexts.set(dbId, ctx);
        this.addDBToList({ dbId, schema, role, creatorDeviceId });
        this.selectDB(dbId);
    }

    async generateConnectionKey(deviceId: string): Promise<string> {
        if (!this.deviceId || !this.selectedDbId) throw new Error('No Device Id found.');

        const { ctx, dbId: resolvedDbId } = this.resolveCtxSync(this.selectedDbId);

        // Load secrets for the current app device (not the target device)
        const secret = this.loadSecrets(resolvedDbId, this.deviceId);
        if (!secret) throw new Error('No secrets found in local storage');

        const bundle = {
            ...secret,
            dekRaw: toB64(secret.dekRaw),
            indexKeyRaw: toB64(secret.indexKeyRaw),
        };

        const device = await ctx.db.getDevice(deviceId);
        if (!device) throw new Error(`Device ${deviceId} not found`);

        const connectionKey = {
            deviceId,
            dbId: resolvedDbId,
            role: device.role,
            schema: ctx.schema,
            secret: bundle,
            creatorDeviceId: ctx.creatorDeviceId
        };

        return JSON.stringify(connectionKey);
    }

    // ---------- Add Device ----------
    async addDevice(newDeviceId: string, role: string) {
        if (!this.selectedDbId || !this.deviceId) return;
    
        const ctx = this.dbContexts.get(this.selectedDbId);
        if (!ctx) throw new Error(`DB ${this.selectedDbId} not loaded`);
        if (ctx.role !== ROLES.CREATOR) throw new Error('Only creator can add devices');
    
        // 🔑 Load secrets for the new device
        const newDeviceSecrets = this.loadSecrets(this.selectedDbId, this.deviceId);
        if (!newDeviceSecrets || !newDeviceSecrets.devicePubJwk) {
            throw new Error(`No secrets found for device ${newDeviceId}`);
        }
    
        const grant: RoleGrant = await issueRoleGrant({
            cryptoManager: ctx.cryptoMgr,
            dbId: this.selectedDbId,
            deviceId: newDeviceId,
            role,
            devicePubJwk: newDeviceSecrets.devicePubJwk
        });
    
        await ctx.db.addOrUpdateDevice({ deviceId: newDeviceId, role, grant });
    }

    // ---------- Sync ----------
    private async startSync(
        db: IndexedDBAbstraction,
        cryptoMgr: CryptoManager,
        deviceId: string,
        dbId: string,
        isCreator: boolean,
        creatorDeviceId: string | null
    ): Promise<CreatorHubSyncManager> {
        const transport = new WebSocketTransport(`ws://localhost:3000?deviceId=${deviceId}`);
        const sync = new CreatorHubSyncManager({
            db,
            transport,
            cryptoManager: cryptoMgr,
            isCreator,
            creatorDeviceId
        });
        await sync.start();
        if (!isCreator) sync.requestInitialSync();
        return sync;
    }

    // ---------- Generic CRUD ----------
    async put(dbId: string, entity: string, value: any) {
        const ctx = this.resolveCtxSync(dbId).ctx;
        await ctx.db.put(entity, value);
    }

    async get(dbId: string, entity: string, id: string) {
        const ctx = this.resolveCtxSync(dbId).ctx;
        return ctx.db.get(entity, id);
    }

    async delete(dbId: string, entity: string, id: string) {
        const ctx = this.resolveCtxSync(dbId).ctx;
        await ctx.db.delete(entity, id);
    }

    async search(dbId: string, entity: string, query: any) {
        const ctx = this.resolveCtxSync(dbId).ctx;
        return ctx.db.search(entity, query);
    }

    async listDevices(dbId: string) {
        const ctx = this.resolveCtxSync(dbId).ctx;
        return ctx.db.listDevices();
    }

    async listRoles(dbId: string) {
        const ctx = this.resolveCtxSync(dbId).ctx;
        return ctx.db.listRoles();
    }

    // ---------- Context Resolver ----------
    private resolveCtxSync(dbId?: string): { ctx: DBContext; dbId: string } {
        const effectiveDbId = dbId ?? this.selectedDbId;
        if (!effectiveDbId) throw new Error('No DB selected and no dbId provided');
        const ctx = this.dbContexts.get(effectiveDbId);
        if (!ctx) throw new Error(`DB ${effectiveDbId} not loaded`);
        return { ctx, dbId: effectiveDbId };
    }
}