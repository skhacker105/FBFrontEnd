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
  issueRoleGrant
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

  constructor() {
    this.deviceId = this.getDeviceId();
    this.dbId = this.getDBId();
  }

  /**
   * Try to restore DB, crypto, and sync state from localStorage.
   */
  async restoreFromLocalStorage(deviceId: string, dbId: string, schema: any): Promise<boolean> {
    const secrets = this.loadSecretsFromLocalStorage(dbId, deviceId);
    if (!secrets) return false;

    // minimal schema — actual schema/policies sync later
    // const schema = { version: 1, stores: {} };
    this.db = new IndexedDBAbstraction({ dbId, deviceId, schema });
    await this.db.init();

    this.cryptoMgr = new CryptoManager({
      deviceId,
      dbId,
      loadSecrets: async () => secrets
    });
    this.db.attachCrypto(this.cryptoMgr);

    // try to rejoin with whatever role is in DB (will be synced/validated)
    await this.db.ensureDevice({ deviceId, role: ROLES.VIEWER });

    // restart sync
    await this.startSync(false);

    return true;
  }

  /**
   * Attach the current deviceId (stored or given externally).
   */
  setDeviceId(deviceId: string) {
    this.deviceId = deviceId;
    localStorage.setItem('myDeviceId', deviceId);
  }

  getDeviceId(): string | null {
    return localStorage.getItem('myDeviceId');
  }

  /**
   * Attach the current dbId (stored or given externally).
   */
  setDBId(dbId: string) {
    this.dbId = dbId;
    localStorage.setItem('myDBId', dbId);
  }

  getDBId(): string | null {
    return localStorage.getItem('myDBId');
  }

  /**
   * Step 1: Device A creates the database (as CREATOR).
   */
  async createDatabaseAsCreator(deviceId: string, dbId: string, schema: any) {
    this.setDeviceId(deviceId);
    this.setDBId(dbId);



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

    // grant creator role to the creator device
    if (this.cryptoMgr.devicePubJwk) {
      const grant: RoleGrant = await issueRoleGrant({
        dskPrivKey: this.cryptoMgr.devicePriv,
        dbId: this.dbId ?? 'no-db',
        deviceId,
        role: 'creator',
        devicePubJwk: this.cryptoMgr.devicePubJwk
      });
      await this.db?.addOrUpdateDevice({ deviceId, role: 'creator', grant });
    }



    await this.startSync(true);

    console.log(`DB ${this.dbId} created by ${deviceId} as CREATOR`);
  }

  /**
   * Step 2: Creator/Admin adds a new device with given role.
   */
  async addDevice(deviceId: string, role: string, devicePubJwk: JsonWebKey) {
    if (!this.cryptoMgr) throw new Error("CryptoMgr not initialized");
    const dskPrivKey = this.cryptoMgr.devicePriv;

    const grant: RoleGrant = await issueRoleGrant({
      dskPrivKey,
      dbId: this.dbId ?? 'no-db',
      deviceId,
      role,
      devicePubJwk
    });

    await this.db?.addOrUpdateDevice({ deviceId, role, grant });
    console.log(`Device ${deviceId} added as ${role}`);
  }

  /**
   * Step 3: Any device joins (B or C).
   */
  async joinAsDevice(deviceId: string, role: string, dbId: string, cryptoSecret: SecretBundle, schema: any) {
    this.setDeviceId(deviceId);
    this.setDBId(dbId);

    this.db = new IndexedDBAbstraction({ dbId, deviceId, schema });
    await this.db.init();

    this.cryptoMgr = new CryptoManager({
      deviceId,
      dbId,
      loadSecrets: async () => cryptoSecret
    });
    this.db.attachCrypto(this.cryptoMgr);

    await this.db.ensureDevice({ deviceId, role });

    await this.startSync(false);

    console.log(`Device ${deviceId} joined as ${role}`);
  }

  /**
   * Utility: start sync manager
   */
  private async startSync(isCreator: boolean) {
    const socket = new WebSocket('ws://localhost:3000'); // replace with real hub server
    const transport = new WebSocketTransport({ socket });

    this.sync = new CreatorHubSyncManager({
      db: this.db!,
      transport,
      cryptoManager: this.cryptoMgr!,
      isCreator
    });
    await this.sync.start();
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
      const parsed = JSON.parse(raw)
      return {
        ...parsed, dekRaw: fromB64(parsed.dekRaw),
        indexKeyRaw: fromB64(parsed.indexKeyRaw)
      };
    } catch (e) {
      console.warn("Failed to parse secrets:", e);
      return null;
    }
  }

  async addTask(id: string, title: string, description: string, status: string) {
    await this.db?.put('tasks', { id, title, description, status });
  }

  async searchTask(text: string) {
    const found = await this.db?.search('tasks', { text, fields: ['title'], minMatch: 'ALL' });
    // console.log('found = ', found);
    return found;
  }

  async listDevices() {
    if (!this.db) throw new Error("DB not initialized");
    const devices = await this.db.listDevices();
    return devices;
  }

  async listRoles() {
    if (!this.db) throw new Error("DB not initialized");
    const devices = await this.db.listRoles();
    return devices;
  }
}


// Utility: serialize Uint8Array into base64
export function toB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}
export function fromB64(s: string): Uint8Array {
  return new Uint8Array([...atob(s)].map(c => c.charCodeAt(0)));
}