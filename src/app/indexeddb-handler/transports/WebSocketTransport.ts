import { BaseTransport } from './BaseTransport';

export class WebSocketTransport extends BaseTransport {
    socket: WebSocket | null;
    private _bound = false;
    constructor({ socket }: { socket: WebSocket | null }) { super(); this.socket = socket; }
    override async connect() {
        if (!this.socket) throw new Error('WebSocket instance required');
        if (this._bound) return;
        this._bound = true;
        this.socket.addEventListener('message', (ev) => {
            try { this['emit']('message', JSON.parse((ev as MessageEvent).data)); } catch { }
        });
    }
    override async send(msg: any) { if (this.socket?.readyState === 1) this.socket.send(JSON.stringify(msg)); }
    override async close() { try { this.socket?.close(); } catch { } }
}
