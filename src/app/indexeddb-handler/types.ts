import { ROLES } from './constants';

export type Role = typeof ROLES[keyof typeof ROLES];

export type RolePermissions = {
    READ?: boolean;
    WRITE?: boolean;
    DELETE?: boolean;
    MANAGE_ROLES?: boolean;
    MANAGE_DEVICES?: boolean;
    MANAGE_SCHEMA?: boolean;
};

export type SchemaStoreDef = {
    keyPath?: string;
    autoIncrement?: boolean;
    indexes?: { name: string; keyPath: string | string[]; options?: IDBIndexParameters }[];
    secureIndex?: string[]; // names of fields to blind-index
};

export type Schema = {
    version: number;
    stores: Record<string, SchemaStoreDef>;
};

export interface RoleGrant {
    type: string;
    createdAt: number;
    dbId: string;
    deviceId: string;
    role: string;
    devicePubJwk: JsonWebKey;
    issuedAt: number;
    sig: string;
}   


export type SecretBundle = {
    dekRaw: Uint8Array;      // 32 bytes
    indexKeyRaw: Uint8Array; // 32 bytes for HMAC
    devicePrivJwk: JsonWebKey;
    devicePubJwk: JsonWebKey;
    dskPubJwk?: JsonWebKey | null;
    dskPrivJwk: JsonWebKey | null;
};
