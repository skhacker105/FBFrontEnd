import { BaseTransport } from './BaseTransport';

export class WebSocketTransport extends BaseTransport {
  url: string;
  private socket: WebSocket | null = null;
  private outboundQueue: any[] = [];
  private reconnectDelay = 1000;
  private maxReconnectDelay = 16000;
  private closedByApp = false;

  constructor(url: string) {
    super();
    this.url = url;
  }

  override async connect() {
    this._connect();
  }

  private _connect() {
    console.log(`[WS] connecting -> ${this.url}`);
    this.closedByApp = false;

    try {
      this.socket = new WebSocket(this.url);
    } catch (err) {
      console.warn('[WS] socket construction failed', err);
      setTimeout(() => this._connect(), this.reconnectDelay);
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);
      return;
    }

    this.socket.onopen = () => {
      console.log('[WS] connected');
      // drain queue
      console.log('this.outboundQueue = ', this.outboundQueue)
      const q = this.outboundQueue.splice(0);
      for (const m of q) this._sendNow(m);
      this.reconnectDelay = 1000;
      this._emit('open');
    };

    this.socket.onmessage = (e: MessageEvent) => {
      try {
        const msg = JSON.parse(e.data);
        console.log('[WS] recv', msg);
        this._emit('message', msg);
      } catch (err) {
        console.warn('[WS] failed to parse message', err);
      }
    };

    this.socket.onclose = (ev) => {
      console.log('[WS] closed', ev && ev.code);
      this._emit('close');
      this.socket = null;
      if (this.closedByApp) return;
      setTimeout(() => this._connect(), this.reconnectDelay);
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);
    };

    this.socket.onerror = (ev) => {
      console.warn('[WS] error', ev);
      // onclose will follow and reconnect
    };
  }

  override async send(msg: any) {
    console.log('[WS] send queued', msg);
    console.log(`Socket in ${this.socket?.readyState} state.`)
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      this._sendNow(msg);
    } else {
      // queue until open
      this.outboundQueue.push(msg);
    }
  }

  private _sendNow(msg: any) {
    try {
      const s = JSON.stringify(msg);
      this.socket?.send(s);
      console.log('[WS] sent', msg);
    } catch (err) {
      console.warn('[WS] send failed, queuing', err);
      this.outboundQueue.push(msg);
    }
  }

  override async close() {
    this.closedByApp = true;
    try { this.socket?.close(); } catch { }
    this.socket = null;
  }
}
