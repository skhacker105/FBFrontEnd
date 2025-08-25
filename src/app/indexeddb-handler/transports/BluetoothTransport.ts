import { BaseTransport } from './BaseTransport';

export class BluetoothTransport extends BaseTransport {
    private _sendFn?: (msg: any) => Promise<void>;
    constructor({ sendFn } = {} as { sendFn?: (msg: any) => Promise<void> }) { super(); this._sendFn = sendFn; }
    setSender(fn: (msg: any) => Promise<void>) { this._sendFn = fn; }
    override async send(msg: any) { if (!this._sendFn) throw new Error('No Bluetooth sender provided'); await this._sendFn(msg); }
    receive(msg: any) { this['_emit']('message', msg); }
}
