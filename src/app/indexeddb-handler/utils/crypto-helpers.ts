export function utf8(str: string) { return new TextEncoder().encode(str); }

export function toB64(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes));
}

export function fromB64(s: string): Uint8Array {
    return new Uint8Array([...atob(s)].map(c => c.charCodeAt(0)));
}

export async function importAesKey(raw: Uint8Array) {
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
export async function exportRawKey(key: CryptoKey) { return new Uint8Array(await crypto.subtle.exportKey('raw', key)); }

export async function genAesKey() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
export async function genSigningKeyPair() {
    return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}
export async function signBytes(privKey: CryptoKey, bytes: Uint8Array) {
    return new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privKey, bytes));
}
export async function verifyBytes(pubKey: CryptoKey, sig: Uint8Array, bytes: Uint8Array) {
    return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, sig, bytes);
}
export async function importPubJwk(jwk: JsonWebKey) {
    return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
}
export async function importPrivJwk(jwk: JsonWebKey) {
    return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
}
export async function hmacKeyFromRaw(raw: Uint8Array) {
    return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}
export async function hmacDigest(key: CryptoKey, bytes: Uint8Array) {
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, bytes));
}
