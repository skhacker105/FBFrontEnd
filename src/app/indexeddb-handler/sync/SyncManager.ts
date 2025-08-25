import { eventTarget } from '../utils/basics';
import { IndexedDBAbstraction } from '../db/IndexedDBAbstraction';
import { BaseTransport } from '../transports/BaseTransport';

export class SyncManager {
    db: IndexedDBAbstraction;
    transport: BaseTransport;
    batchMs: number;
    targetPeers: 'broadcast' | string | string[];
    private _buffer: any[] = [];
    private _timer: any = null;
    private _ev = eventTarget();

    constructor({ db, transport, batchMs = 150, targetPeers = 'broadcast' }:
        { db: IndexedDBAbstraction; transport: BaseTransport; batchMs?: number; targetPeers?: 'broadcast' | string | string[] }) {
        this.db = db;
        this.transport = transport;
        this.batchMs = batchMs;
        this.targetPeers = targetPeers;
    }

    on(type: string, h: any) { this._ev.on(type, h); }
    off(type: string, h: any) { this._ev.off(type, h); }

    async start() {
        await this.transport.connect();
        // local change queueing
        this.db['on']('local-change', (ev: Event) => this._queue((ev as CustomEvent).detail));
        // remote hook (no-op locally; here for completeness)
        this.transport.on('message', async (_msg: any) => { });
    }

    async stop() { await this.transport.close(); }

    private _queue(change: any) {
        this._buffer.push(change);
        if (!this._timer) this._timer = setTimeout(() => this._flush(), this.batchMs);
    }

    protected async _flush() {
        // Local-only polish: do nothing. In future, send batched changes over transport.
        this._buffer.splice(0, this._buffer.length);
        this._timer = null;
    }
}
