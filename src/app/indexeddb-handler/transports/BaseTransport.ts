import { eventTarget } from '../utils/basics';

export class BaseTransport {
    private _ev = eventTarget();
    on(type: string, h: any) { this._ev.on(type, h); }
    off(type: string, h: any) { this._ev.off(type, h); }
    protected emit(type: string, detail?: any) { this._ev.emit(type, detail); }
    async connect() { }
    async send(_msg: any) { throw new Error('send not implemented'); }
    async close() { }
}
