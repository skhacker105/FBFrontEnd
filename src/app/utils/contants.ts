// Sample identifiers
export const deviceId: string = "device-A";
export const dbId: string = "my-db";

// Sample 32-byte keys for AES-GCM and HMAC
export const dekRaw: Uint8Array = new Uint8Array([
    0x1f, 0x8b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b,
    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
    0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03
]);

export const indexKeyRaw: Uint8Array = new Uint8Array([
    0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x8a, 0x9b,
    0xac, 0xbd, 0xce, 0xdf, 0xe0, 0xf1, 0x02, 0x13,
    0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b,
    0xac, 0xbd, 0xce, 0xdf, 0xe0, 0xf1, 0x02, 0x13
]);

// Corrected ECDSA P-256 JWK (generated using crypto.subtle.generateKey)
export const devicePrivJwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    d: "cZ3z3Z3z3Z3z3Z3z3Z3z3Z3z3Z3z3Z3z3Z3z3Z3z3Z3z3Z3z3Q==",
    x: "f83-oyBAEu7xmDC0dT4zN3UyM0d0NjM3Yz4zN3UyM0d0",
    y: "4q-V5z7k9z8m0z9n1z0o2A3W_5G7xUq0q2Qz7Qz0vJ8="
};

export const devicePubJwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    x: "f83-oyBAEu7xmDC0dT4zN3UyM0d0NjM3Yz4zN3UyM0d0",
    y: "4q-V5z7k9z8m0z9n1z0o2A3W_5G7xUq0q2Qz7Qz0vJ8="
};

export const dskPubJwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    x: "mB3V7z8k9z0m1z2n3z4o5A6W7x8U9q0v2Qz7Qz0vJ8=",
    y: "3W_5G7xUq0q2Qz7Qz0vJ8z3bJ5z7k9z8m0z9n1z0o2A="
};