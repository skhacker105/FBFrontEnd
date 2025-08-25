import { BaseTransport } from './BaseTransport';

export class HttpTransport extends BaseTransport {
    baseUrl: string;
    deviceId: string;
    pollIntervalMs: number;
    headers: Record<string, string>;
    private _timer: any = null;

    constructor({ baseUrl, deviceId, pollIntervalMs = 2000, headers = {} }:
        { baseUrl: string; deviceId: string; pollIntervalMs?: number; headers?: Record<string, string> }) {
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
                    (arr || []).forEach((m: any) => this['emit']('message', m));
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
