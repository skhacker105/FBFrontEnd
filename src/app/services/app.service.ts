import { Injectable } from '@angular/core';
import { CreatorHubSyncManager, CryptoManager, IndexedDBAbstraction, ROLES, WebSocketTransport } from '../utils/indexeddb-secure-sync.full';
import { dekRaw, indexKeyRaw, devicePrivJwk, devicePubJwk, dskPubJwk } from '../utils/contants';

@Injectable({
  providedIn: 'root'
})
export class AppService {

  title = 'First Book';

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
          indexes: [{ name: 'byStatus', keyPath: 'status' }],
          secureIndex: ['title', 'description'] // enables encrypted partial search
        }
      }
    };

    console.log('schema = ', schema);
    const db = new IndexedDBAbstraction({ dbId, deviceId, schema });
    await db.init();

    console.log('db initiated ');
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

    console.log('crypto manager ');
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
    // await db.addOrUpdateDevice({ deviceId:'device-B', role:'analyst', grant });
    await db.addOrUpdateDevice({ deviceId:'device-B', role:'analyst' });

    // Use CreatorHubSyncManager so all devices sync via creator
    const socket = new WebSocket('wss://example.com/sync');
    const transport = new WebSocketTransport({ socket });

    const sync = new CreatorHubSyncManager({ db, transport, cryptoManager: cryptoMgr, isCreator: true });
    await sync.start();

    // CRUD (auto-encrypted; search uses blind index):
    await db.put('tasks', { id:'t1', title:'hello world', description:'secret note', status:'open' });
    const found = await db.search('tasks', { text:'hell', fields:['title'], minMatch:'ALL' });

    // Per-record ACL:
    await db.setRecordAcl('tasks','t1',{ read:['analyst','viewer'], write:['analyst'] });
  
  }
}
