import { Injectable } from '@angular/core';
import {
  CreatorHubSyncManager,
  CryptoManager,
  IndexedDBAbstraction,
  ROLES,
  RoleGrant,
  SecretBundle,
  WebSocketTransport,
  bootstrapSecrets,
  fromB64,
  issueRoleGrant,
  toB64
} from '../indexeddb-handler';

@Injectable({
  providedIn: 'root'
})
export class AppService {
  title = 'First Book';

  db: IndexedDBAbstraction | undefined;
  cryptoMgr: CryptoManager | undefined;
  sync: CreatorHubSyncManager | undefined;
  dbId: string | null;
  deviceId: string | null = null;
  creatorDeviceId: string | null = null;

  constructor() {
    this.deviceId = this.getDeviceId();
    this.dbId = this.getDBId();
    this.creatorDeviceId = this.getCreatorDeviceId();
  }

  // ---------- LocalStorage helpers ----------
  setDeviceId(deviceId: string) {
    this.deviceId = deviceId;
    localStorage.setItem('myDeviceId', deviceId);
  }

  getDeviceId(): string | null {
    return localStorage.getItem('myDeviceId');
  }

  setDBId(dbId: string) {
    this.dbId = dbId;
    localStorage.setItem('myDBId', dbId);
  }

  getDBId(): string | null {
    return localStorage.getItem('myDBId');
  }

  setCreatorDeviceId(creatorDeviceId: string) {
    this.creatorDeviceId = creatorDeviceId;
    localStorage.setItem('creatorDeviceId', creatorDeviceId);
  }

  getCreatorDeviceId(): string | null {
    return localStorage.getItem('creatorDeviceId');
  }

  private saveSecretsToLocalStorage(dbId: string, deviceId: string, bundle: SecretBundle) {
    const key = `secrets_${dbId}_${deviceId}`;
    localStorage.setItem(key, JSON.stringify({
      ...bundle,
      dekRaw: toB64(bundle.dekRaw),
      indexKeyRaw: toB64(bundle.indexKeyRaw)
    }));
  }

  loadSecretsFromLocalStorage(dbId: string, deviceId: string): SecretBundle | null {
    const key = `secrets_${dbId}_${deviceId}`;
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw);
      return {
        ...parsed,
        dekRaw: fromB64(parsed.dekRaw),
        indexKeyRaw: fromB64(parsed.indexKeyRaw)
      };
    } catch (e) {
      console.warn('Failed to parse secrets:', e);
      return null;
    }
  }

  // ---------- Restore after refresh ----------
  async restoreFromLocalStorage(deviceId: string, dbId: string, schema: any): Promise<boolean> {
    const secrets = this.loadSecretsFromLocalStorage(dbId, deviceId);
    if (!secrets) return false;

    this.db = new IndexedDBAbstraction({ dbId, deviceId, schema });
    await this.db.init();

    this.cryptoMgr = new CryptoManager({
      deviceId,
      dbId,
      loadSecrets: async () => secrets
    });
    this.db.attachCrypto(this.cryptoMgr);

    await this.db.ensureDevice({ deviceId, role: ROLES.VIEWER });

    const device = await this.db.getDevice(deviceId);
    const isAdmin = device.role === ROLES.CREATOR;
    await this.startSync(isAdmin, this.creatorDeviceId);
    return true;
  }

  resetDevice(removeDB = true) {
    localStorage.removeItem(`secrets_${this.dbId}_${this.deviceId}`);
    localStorage.removeItem('myDBId');
    localStorage.removeItem('creatorDeviceId');
    if (removeDB) {
      indexedDB.deleteDatabase('idb:' + (this.dbId ?? ''));
    }
  }

  // ---------- Main flows ----------
  async createDatabaseAsCreator(deviceId: string, dbId: string, schema: any) {
    this.setDeviceId(deviceId);
    this.setDBId(dbId);
    this.setCreatorDeviceId(deviceId);

    this.db = new IndexedDBAbstraction({ dbId, deviceId, schema });
    await this.db.init();

    let cryptoSecret = this.loadSecretsFromLocalStorage(dbId, deviceId)
      ?? await bootstrapSecrets(dbId, deviceId, true);
    this.saveSecretsToLocalStorage(dbId, deviceId, cryptoSecret);

    this.cryptoMgr = new CryptoManager({
      deviceId,
      dbId,
      loadSecrets: async () => cryptoSecret
    });
    this.db.attachCrypto(this.cryptoMgr);

    await this.db.ensureDevice({ deviceId, role: ROLES.CREATOR });

    await this.db.setPolicy('tasks', {
      defaults: {
        read: [ROLES.CREATOR, ROLES.ADMIN, ROLES.EDITOR, ROLES.VIEWER],
        write: [ROLES.CREATOR, ROLES.ADMIN]
      },
      fields: {
        secret: { read: [ROLES.CREATOR, ROLES.ADMIN], write: [ROLES.CREATOR, ROLES.ADMIN] }
      }
    });

    await this.db.addCustomRole('analyst', {
      READ: true,
      WRITE: false,
      DELETE: false,
      MANAGE_ROLES: false,
      MANAGE_DEVICES: false,
      MANAGE_SCHEMA: false
    });

    if (this.cryptoMgr.devicePubJwk) {
      const grant: RoleGrant = await issueRoleGrant({
        cryptoManager: this.cryptoMgr,
        dbId: this.dbId ?? 'no-db',
        deviceId,
        role: ROLES.CREATOR,
        devicePubJwk: this.cryptoMgr.devicePubJwk
      });
      await this.db?.addOrUpdateDevice({ deviceId, role: ROLES.CREATOR, grant });
    }

    await this.startSync(true);
    console.log(`DB ${this.dbId} created by ${deviceId} as CREATOR`);
  }

  async addDevice(deviceId: string, role: string, devicePubJwk: JsonWebKey) {
    if (!this.cryptoMgr) throw new Error('CryptoMgr not initialized');

    const grant: RoleGrant = await issueRoleGrant({
      cryptoManager: this.cryptoMgr,
      dbId: this.dbId ?? 'no-db',
      deviceId,
      role,
      devicePubJwk
    });

    await this.db?.addOrUpdateDevice({ deviceId, role, grant });
    console.log(`Device ${deviceId} added as ${role}`);
  }

  async joinAsDevice(deviceId: string, role: string, dbId: string, cryptoSecret: SecretBundle, schema: any, creatorDeviceId: string) {
    this.setDeviceId(deviceId);
    this.setDBId(dbId);
    this.setCreatorDeviceId(creatorDeviceId);
    this.saveSecretsToLocalStorage(dbId, deviceId, cryptoSecret);

    this.db = new IndexedDBAbstraction({ dbId, deviceId, schema });
    await this.db.init();

    this.cryptoMgr = new CryptoManager({
      deviceId,
      dbId,
      loadSecrets: async () => cryptoSecret
    });
    this.db.attachCrypto(this.cryptoMgr);

    await this.db.ensureDevice({ deviceId, role });

    await this.startSync(false, creatorDeviceId);
    console.log(`Device ${deviceId} joined as ${role}`);
  }

  // ---------- Sync ----------
  private async startSync(isCreator: boolean, creatorDeviceId: string | null = null) {
    const transport = new WebSocketTransport(`ws://localhost:3000?deviceId=${this.deviceId}`);

    this.sync = new CreatorHubSyncManager({
      db: this.db!,
      transport,
      cryptoManager: this.cryptoMgr!,
      isCreator,
      creatorDeviceId
    });
    await this.sync.start();

    if (!isCreator) {
      this.sync.requestInitialSync(); // ✅ correct method name
    }
  }

  // ---------- DB helpers ----------
  async addTask(id: string, title: string, description: string, status: string) {
    await this.db?.put('tasks', { id, title, description, status });
  }

  async searchTask(text: string) {
    return await this.db?.search('tasks', { text, fields: ['title'], minMatch: 'ALL' });
  }

  async listDevices() {
    if (!this.db) throw new Error('DB not initialized');
    return await this.db.listDevices();
  }

  async listRoles() {
    if (!this.db) throw new Error('DB not initialized');
    return await this.db.listRoles();
  }
}

// ---------- Utility ----------
// export function toB64(bytes: Uint8Array): string {
//   return btoa(String.fromCharCode(...bytes));
// }

// export function fromB64(s: string): Uint8Array {
//   return new Uint8Array([...atob(s)].map(c => c.charCodeAt(0)));
// }
