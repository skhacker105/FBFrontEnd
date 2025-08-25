import { SecretBundle } from '../types';
import { b64 } from '../utils/crypto-helpers';

/**
 * A portable connection bundle that Creator generates for a new device (B).
 * It includes: dbId, schema, DEK/IndexKey, DSK public key, and a role grant signed by creator DSK.
 * The new device keeps/uses its own device keypair; the grant binds to deviceB's pubkey.
 */
export type ConnectionBundle = {
    dbId: string;
    schema: any;
    secrets: {
        dekRawB64: string;
        indexKeyRawB64: string;
        dskPubJwk?: JsonWebKey;
    };
    grant: {
        dbId: string;
        deviceId: string;
        role: string;
        devicePubJwk: JsonWebKey;
        issuedAt: number;
        sig: string; // signature by DSK over the grant payload
    };
};

/**
 * Build a shareable connection string (base64 JSON) for Device B.
 * The creator passes in its own SecretBundle to extract dek/indexKey and dskPubJwk.
 */
export function buildConnectionString(args: {
    dbId: string;
    schema: any;
    creatorSecrets: SecretBundle;
    grant: {
        dbId: string;
        deviceId: string;
        role: string;
        devicePubJwk: JsonWebKey;
        issuedAt: number;
        sig: string;
    };
}): string {
    const { dbId, schema, creatorSecrets, grant } = args;
    const bundle: ConnectionBundle = {
        dbId,
        schema,
        secrets: {
            dekRawB64: b64(creatorSecrets.dekRaw),
            indexKeyRawB64: b64(creatorSecrets.indexKeyRaw),
            dskPubJwk: creatorSecrets.dskPubJwk || undefined
        },
        grant
    };
    const json = JSON.stringify(bundle);
    return btoa(unescape(encodeURIComponent(json)));
}

export function parseConnectionString(s: string): ConnectionBundle {
    const json = decodeURIComponent(escape(atob(s)));
    const obj = JSON.parse(json);
    return obj as ConnectionBundle;
}
