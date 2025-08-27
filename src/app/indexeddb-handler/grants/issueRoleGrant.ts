import { CryptoManager } from '../crypto/CryptoManager';
import { RoleGrant } from '../types';

export async function issueRoleGrant(opts: {
  cryptoManager: CryptoManager;
  dbId: string;
  deviceId: string;
  role: string;
  devicePubJwk: JsonWebKey;
}): Promise<RoleGrant> {
  const { cryptoManager, dbId, deviceId, role, devicePubJwk } = opts;

  const payload = {
    dbId,
    deviceId,
    role,
    devicePubJwk,
    issuedAt: Date.now()
  };

  const sig = await cryptoManager.signWithDSK(payload);

  const grant: RoleGrant = {
    type: 'role_grant',     // ✅ required field
    createdAt: Date.now(),  // ✅ required field
    ...payload,
    sig
  };

  return grant;
}
