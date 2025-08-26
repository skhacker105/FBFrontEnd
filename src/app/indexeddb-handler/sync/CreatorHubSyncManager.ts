import { IndexedDBAbstraction } from '../db/IndexedDBAbstraction';
import { CryptoManager } from '../crypto/CryptoManager';
import { ROLES } from '../constants';
import { WebSocketTransport } from '../transports/WebSocketTransport';
import { SyncManager } from './SyncManager';

type SyncStartMode = 'creator' | 'device';

export class CreatorHubSyncManager extends SyncManager {
    private crypto: CryptoManager;
    private mode: SyncStartMode; // 'creator' or 'device'
    private lastAppliedLamport = 0;
    private syncing = false;
    private creatorDeviceId: string | null;

    constructor(opts: {
        db: IndexedDBAbstraction;
        cryptoManager: CryptoManager;
        transport: WebSocketTransport;
        isCreator: boolean;
        creatorDeviceId: string | null;
    }) {
        super({ db: opts.db, transport: opts.transport, batchMs: 150, targetPeers: opts.isCreator ? 'broadcast' : ['creator'] });
        this.crypto = opts.cryptoManager;
        this.creatorDeviceId = opts.creatorDeviceId;
        this.mode = opts.isCreator ? 'creator' : 'device';
    }

    override async start() {
        // restore last lamport seen for "hub" peer (single room scenario)
        const saved = await this.db.getPeerSyncState(this._peerKey());
        this.lastAppliedLamport = Number(saved?.lastLamport || 0);

        await this.transport.connect();

        // listen to messages
        this.transport.on('message', async (m: any) => {
            console.log('[CreatorHubSyncManager] Incoming message:', m);
            await this._onMessage(m.detail);
        });

        this.transport.on('open', () => {
            console.log('[CreatorHubSyncManager] Transport open');
            if (this.mode === 'device') this.requestInitialSync();
        });

        // forward local-changes to wire (after initial full sync)
        this.db.on('local-change', async (ev: any) => {
            if (!this.syncing) {
                const change = ev.detail || ev; // CustomEvent or raw
                const devices = this.mode === 'device'
                    ? [{deviceId: this.creatorDeviceId}]
                    : (await this.db.listDevices()).filter(d => d.deviceId)
                console.log('[CreatorHubSyncManager] Local change → sending', change);

                for(let device of devices) {
                    this.transport.send({
                        type: 'sync-data-update',
                        dbId: this.db.dbId,
                        toDeviceId: device.deviceId,
                        fromDeviceId: this.db.deviceId,
                        change
                    });
                }
                
            }
        });

        // device side triggers initial sync request immediately if already open
        // if (this.mode === 'device') this.requestInitialSync();
    }

    private _peerKey() { return 'hub'; }

    // =============== Public API ===============

    /** For device — send first sync request (idempotent, safe after refresh). */
    requestInitialSync() {
        console.log('[CreatorHubSyncManager] Sending sync-request from device', this.db.deviceId, 'lamport', this.lastAppliedLamport);
        this.transport.send({
            toDeviceId: this.creatorDeviceId,
            type: 'sync-request',
            dbId: this.db.dbId,
            fromDeviceId: this.db.deviceId,
            fromLamport: this.lastAppliedLamport || 0
        });
    }

    // =============== Incoming messages ===============

    private async _onMessage(msg: any) {
        if (!msg || msg.dbId !== this.db.dbId) return;

        switch (msg.type) {
            case 'sync-request':
                if (this.mode === 'creator') await this._handleSyncRequestFromDevice(msg);
                break;
            case 'sync-response':
                if (this.mode === 'device') await this._handleSyncResponseOnDevice(msg);
                break;
            case 'sync-data-update':
                await this._handleDataUpdate(msg);
                break;
            case 'sync-end':
                this.syncing = false;
                console.log('[CreatorHubSyncManager] Sync finished');
                break;
        }
    }

    // =============== Creator branch ===============

    private async _handleSyncRequestFromDevice(msg: { fromLamport: number; fromDeviceId: string }) {
        this.syncing = true;
        const fromLamport = Number(msg.fromLamport || 0);
        console.log('[CreatorHubSyncManager] Device requested sync from lamport', fromLamport);

        if (fromLamport <= 0) {
            // FULL SNAPSHOT
            const snapshot = await this.db.exportCipherSnapshot();

            // stream all rows
            console.log('snapshot = ', snapshot)
            const upsertLookup: any = {
                '_devices': 'device_upsert',
                '_roles': 'role_upsert',
                '_policies': 'policy_upsert'
            }
            for (const [store, rows] of Object.entries(snapshot)) {
                if (['_changelog', '_peerSync'].includes(store)) continue;
                for (const r of rows) {
                    let change: any;
                    if (r && typeof r === 'object' && 'id' in r && '_enc' in r) {
                        change = { type: 'upsert', store, key: r.id, value: r._enc, enc: true, lamport: 0, deviceId: this.db.deviceId };
                    } else if (store.startsWith('_')) {
                        change = {
                            type: upsertLookup[store] ?? '',
                            store,
                            key: (r as any)?.id || (r as any)?.deviceId || (r as any)?.role || (r as any)?.store,
                            value: r,
                            lamport: 0,
                            deviceId: this.db.deviceId
                        };
                    }
                    console.log('[CreatorHubSyncManager] Sending row', change);
                    this.transport.send({ type: 'sync-data-update', dbId: this.db.dbId, toDeviceId: msg.fromDeviceId, fromDeviceId: this.db.deviceId, change });
                }
            }

            this.transport.send({ type: 'sync-end', dbId: this.db.dbId, toDeviceId: msg.fromDeviceId, fromDeviceId: this.db.deviceId });
            this.syncing = false;
        } else {
            // DELTA
            const changes = await this.db.getChangesSince(fromLamport);
            this.transport.send({ type: 'sync-response', dbId: this.db.dbId, mode: 'delta', toDeviceId: msg.fromDeviceId, fromDeviceId: this.db.deviceId });
            console.log('[CreatorHubSyncManager] Sending sync-response (delta)', changes.length, 'changes');

            for (const change of changes) {
                this.transport.send({ type: 'sync-data-update', dbId: this.db.dbId, toDeviceId: msg.fromDeviceId, fromDeviceId: this.db.deviceId, change });
            }
            this.transport.send({ type: 'sync-end', dbId: this.db.dbId, toDeviceId: msg.fromDeviceId, fromDeviceId: this.db.deviceId });
            this.syncing = false;
        }
    }

    // =============== Device branch ===============

    private async _handleSyncResponseOnDevice(msg: any) {
        this.syncing = true;
        console.log('[CreatorHubSyncManager] Received sync-response mode=', msg.mode);

        if (msg.mode === 'full') {
            if (msg.schema) {
                await this.db.ensureSchema(msg.schema);
                console.log('[CreatorHubSyncManager] Applied schema from full sync');
            }
        }
        // actual rows come as sync-data-update
    }

    private async _handleDataUpdate(msg: any) {
        const change = msg.change;
        console.log('[CreatorHubSyncManager] Applying remote change', change);
        await this.db.applyRemoteChange(change);
        const lamport = Number(change?.lamport || 0);
        if (lamport > this.lastAppliedLamport) {
            this.lastAppliedLamport = lamport;
            await this.db.setPeerSyncState(this._peerKey(), this.lastAppliedLamport);
            console.log('[CreatorHubSyncManager] Updated lamport →', this.lastAppliedLamport);
        }
    }
}
