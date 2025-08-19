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

// Sample ECDSA P-256 private and public JWK
export const devicePrivJwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    d: "q_Vb3a8vF5z1J7x9K3m2zQ8X9w0v2j3k4l5m6n7o8p",
    x: "0Y2Z3k4l5m6n7o8p9q0r1s2t3u4v5w6x7y8z9A0B1C2",
    y: "D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3"
};

export const devicePubJwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    x: "0Y2Z3k4l5m6n7o8p9q0r1s2t3u4v5w6x7y8z9A0B1C2",
    y: "D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3"
};

export const dskPubJwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    x: "a1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1",
    y: "V2W3X4Y5Z6A7B8C9D0E1F2G3H4I5J6K7L8M9N0O1P2"
};
