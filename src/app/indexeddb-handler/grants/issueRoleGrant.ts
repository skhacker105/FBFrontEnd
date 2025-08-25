import { RoleGrant } from '../types';
import { utf8, b64, signBytes } from '../utils/crypto-helpers';

export async function issueRoleGrant(
    { dskPrivKey, dbId, deviceId, role, devicePubJwk, expiresAt = null }:
        { dskPrivKey: CryptoKey; dbId: string; deviceId: string; role: string; devicePubJwk: JsonWebKey; expiresAt?: number | null }
): Promise<RoleGrant> {
    const payload = { type: 'RoleGrant', dbId, deviceId, role, devicePubJwk, createdAt: Date.now(), expiresAt };
    const sig = b64(await signBytes(dskPrivKey, utf8(JSON.stringify(payload))));
    return { ...payload, sig } as RoleGrant;
}
