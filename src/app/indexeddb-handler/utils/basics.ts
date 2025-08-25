export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function uid(prefix = 'id') {
    return `${prefix}_${Math.random().toString(36).slice(2)}_${Date.now()}`;
}

export function toPromise<T = any>(req: IDBRequest<T>): Promise<T> {
    return new Promise((resolve, reject) => {
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

export function eventTarget() {
    const et = new EventTarget();
    return {
        target: et,
        on: (type: string, handler: EventListenerOrEventListenerObject, opts?: boolean | AddEventListenerOptions) =>
            et.addEventListener(type, handler, opts),
        off: (type: string, handler: EventListenerOrEventListenerObject, opts?: boolean | EventListenerOptions) =>
            et.removeEventListener(type, handler, opts),
        emit: (type: string, detail?: any) => et.dispatchEvent(new CustomEvent(type, { detail }))
    };
}
