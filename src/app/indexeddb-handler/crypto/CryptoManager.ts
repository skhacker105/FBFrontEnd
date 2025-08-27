import { SecretBundle } from '../types';
import { ngrams } from '../utils/text';
import {
    utf8, fromB64, importAesKey, exportRawKey, genAesKey, genSigningKeyPair,
    signBytes, verifyBytes, importPubJwk, importPrivJwk, hmacKeyFromRaw, hmacDigest, toB64
} from '../utils/crypto-helpers';

export async function bootstrapSecrets(dbId: string, deviceId: string, isCreator = false): Promise<SecretBundle> {
    const aesKey = await genAesKey();
    const dekRaw = await exportRawKey(aesKey);

    const indexKey = await genAesKey();
    const indexKeyRaw = await exportRawKey(indexKey);

    const { publicKey, privateKey } = await genSigningKeyPair();
    const devicePubJwk = await crypto.subtle.exportKey('jwk', publicKey);
    const devicePrivJwk = await crypto.subtle.exportKey('jwk', privateKey);

    let dskPubJwk: JsonWebKey | null = null;
    let dskPrivJwk: JsonWebKey | null = null;
    if (isCreator) {
        const { publicKey: dskPub, privateKey: dskPriv } = await genSigningKeyPair();
        dskPubJwk = await crypto.subtle.exportKey('jwk', dskPub);
        dskPrivJwk = await crypto.subtle.exportKey('jwk', dskPriv);
    }

    return {
        dekRaw,
        indexKeyRaw,
        devicePrivJwk: devicePrivJwk as JsonWebKey,
        devicePubJwk: devicePubJwk as JsonWebKey,
        dskPubJwk,
        dskPrivJwk
    };
}

export class CryptoManager {
    deviceId: string;
    dbId: string;
    loadSecrets: () => Promise<SecretBundle>;
    ready: Promise<void>;
  
    private dek!: CryptoKey;
    private indexKey!: CryptoKey;
    private devicePub!: CryptoKey;
    private devicePriv!: CryptoKey;
    dskPub: CryptoKey | null = null;
    private dskPriv: CryptoKey | null = null;
  
    devicePubJwk?: JsonWebKey;
    dskPubJwk?: JsonWebKey;
    dskPrivJwk?: JsonWebKey;
  
    constructor({ deviceId, dbId, loadSecrets }: { deviceId: string; dbId: string; loadSecrets: () => Promise<SecretBundle> }) {
      this.deviceId = deviceId;
      this.dbId = dbId;
      this.loadSecrets = loadSecrets;
      this.ready = this._init();
    }
  
    private async _init() {
      const s = await this.loadSecrets();
      if (!s) throw new Error('Crypto secrets not provided. Provide per-device secrets from secure storage.');
      this.dek = await importAesKey(s.dekRaw);
      this.indexKey = await hmacKeyFromRaw(s.indexKeyRaw);
      this.devicePub = await importPubJwk(s.devicePubJwk);
      this.devicePriv = await importPrivJwk(s.devicePrivJwk);
      this.dskPub = s.dskPubJwk ? await importPubJwk(s.dskPubJwk) : null;
      this.dskPriv = s.dskPrivJwk ? await importPrivJwk(s.dskPrivJwk) : null;
      this.devicePubJwk = s.devicePubJwk;
      this.dskPubJwk = s.dskPubJwk || undefined;
      this.dskPrivJwk = s.dskPrivJwk || undefined;
    }
  
    async encryptJson(obj: any) {
      await this.ready;
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = new Uint8Array(
        await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.dek, utf8(JSON.stringify(obj)))
      );
      return { iv: toB64(iv), ct: toB64(ct) };
    }
  
    async decryptJson(payload: { iv: string; ct: string } | null) {
      await this.ready;
      if (!payload) return null;
      const iv = fromB64(payload.iv); const ct = fromB64(payload.ct);
      const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, this.dek, ct.buffer));
      return JSON.parse(new TextDecoder().decode(pt));
    }
  
    async blindTokens(str: string, n = 3) {
      await this.ready;
      const toks = ngrams(str, n);
      const out: string[] = [];
      for (const t of toks) out.push(toB64(await hmacDigest(this.indexKey, utf8(t))));
      return out;
    }
  
    async sign(obj: any) {
      await this.ready;
      return toB64(await signBytes(this.devicePriv, utf8(JSON.stringify(obj))));
    }
  
    async verifyWithDSKSignature(sigB64: string, obj: any) {
      if (!this.dskPub) return false;
      const sig = fromB64(sigB64);
      return !!(await verifyBytes(this.dskPub, sig, utf8(JSON.stringify(obj))));
    }
  
    async verifyWithDeviceSignature(pubJwk: JsonWebKey, sigB64: string, obj: any) {
      const pub = await importPubJwk(pubJwk);
      return !!(await verifyBytes(pub, fromB64(sigB64), utf8(JSON.stringify(obj))));
    }
  
    // Creator-only helper to sign a RoleGrant with the DSK private key
    async signWithDSK(obj: any): Promise<string> {
      await this.ready;
      if (!this.dskPriv) throw new Error('DSK private key not available on this device');
      return toB64(await signBytes(this.dskPriv, utf8(JSON.stringify(obj))));
    }
  }
