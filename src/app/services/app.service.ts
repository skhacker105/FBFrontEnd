import { Injectable } from '@angular/core';
import { CreatorHubSyncManager, CryptoManager, IndexedDBAbstraction, ROLES, RoleGrant, SecretBundle, WebSocketTransport, bootstrapSecrets, issueRoleGrant } from '../utils/indexeddb-secure-sync.full';
import { dekRaw, indexKeyRaw, devicePrivJwk, devicePubJwk, dskPubJwk } from '../utils/contants';

@Injectable({
  providedIn: 'root'
})
export class AppService {

  title = 'First Book';
  db: IndexedDBAbstraction | undefined;

  constructor() {
    this.run();
  }

  async run() {

    const dbId = 'my-db1';
    const deviceId = 'device-A';

    const schema = {
      version: 1,
      stores: {
        tasks: {
          keyPath: 'id',
          indexes: [{ name: 'byTitle', keyPath: 'title', options: { multiEntry: true } }],
          secureIndex: ['title', 'description', 'status'] // enables encrypted partial search
        }
      }
    };

    const db = new IndexedDBAbstraction({ dbId, deviceId, schema });
    this.db = db;
    await db.init();

    // Attach per-device crypto (keys should come from secure OS store, not IndexedDB)
    let cryptoSecret = this.loadSecretsFromLocalStorage(dbId, deviceId) ?? await bootstrapSecrets(dbId, deviceId, true);
    this.saveSecretsToLocalStorage(dbId, deviceId, cryptoSecret);
    const cryptoMgr = new CryptoManager({
      deviceId, dbId,
      loadSecrets: async () => (cryptoSecret)
    });
    db.attachCrypto(cryptoMgr);

    // Bootstrap creator on first run
    await db.ensureDevice({ deviceId, role: ROLES.CREATOR });

    // Configure role policy (creator-only)
    await db.setPolicy('tasks', {
      defaults: {
        read: [ROLES.CREATOR, ROLES.ADMIN, ROLES.EDITOR, ROLES.VIEWER],
        write: [ROLES.CREATOR, ROLES.ADMIN, ROLES.EDITOR]
      },
      fields: {
        secret: { read: [ROLES.CREATOR, ROLES.ADMIN], write: [ROLES.CREATOR, ROLES.ADMIN] }
      }
    });

    // // Add custom role (creator-only)
    await db.addCustomRole('analyst', { READ: true, WRITE: false, DELETE: false, MANAGE_ROLES: false, MANAGE_DEVICES: false, MANAGE_SCHEMA: false });

    // // Grant device role with signed grant (creator issues)
    const grantVal = await issueRoleGrant({ dskPrivKey: cryptoMgr.devicePriv, dbId, deviceId, role: 'analyst', devicePubJwk });
    const grant: RoleGrant = grantVal;
    if (grant)
      await db.addOrUpdateDevice({ deviceId: 'device-A', role: 'creator', grant });
    // await db.addOrUpdateDevice({ deviceId: 'device-B', role: 'analyst' });

    // // Use CreatorHubSyncManager so all devices sync via creator
    const socket = new WebSocket('https://echo.websocket.org/');
    const transport = new WebSocketTransport({ socket });

    const sync = new CreatorHubSyncManager({ db, transport, cryptoManager: cryptoMgr, isCreator: true });
    await sync.start();
  }

  // Save bundle into localStorage
  saveSecretsToLocalStorage(dbId: string, deviceId: string, bundle: SecretBundle) {
    const key = `secrets_${dbId}_${deviceId}`;
    const obj = {
      dskPrivJwk: bundle.dskPrivJwk,
      dekRaw: toB64(bundle.dekRaw),
      indexKeyRaw: toB64(bundle.indexKeyRaw),
      devicePrivJwk: bundle.devicePrivJwk,
      devicePubJwk: bundle.devicePubJwk,
      dskPubJwk: bundle.dskPubJwk
    };
    localStorage.setItem(key, JSON.stringify(obj));
  }

  // Load bundle from localStorage if present
  loadSecretsFromLocalStorage(dbId: string, deviceId: string): SecretBundle | null {
    const key = `secrets_${dbId}_${deviceId}`;
    const raw = localStorage.getItem(key);
    if (!raw) return null;

    try {
      const parsed = JSON.parse(raw);
      return {
        dskPrivJwk: parsed.dskPrivJwk,
        dekRaw: fromB64(parsed.dekRaw),
        indexKeyRaw: fromB64(parsed.indexKeyRaw),
        devicePrivJwk: parsed.devicePrivJwk,
        devicePubJwk: parsed.devicePubJwk,
        dskPubJwk: parsed.dskPubJwk
      };
    } catch (e) {
      console.warn("Failed to parse secrets:", e);
      return null;
    }
  }

  async addTask1() {
    await this.db?.put('tasks', { id: 't1', title: 'hello world', description: 'secret note', status: 'open' });
  }

  async searchTask1() {
    const found = await this.db?.search('tasks', { text: 'hello', fields: ['title'], minMatch: 'ALL' });
    console.log('found = ', found)
  }
}

// Utility: serialize Uint8Array into base64
function toB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}
function fromB64(s: string): Uint8Array {
  return new Uint8Array([...atob(s)].map(c => c.charCodeAt(0)));
}
