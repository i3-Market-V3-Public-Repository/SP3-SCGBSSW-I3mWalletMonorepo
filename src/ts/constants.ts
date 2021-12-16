export const HASH_ALGS = ['SHA-256', 'SHA-384', 'SHA-512'] as const
export const SIGNING_ALGS = ['ES256', 'ES384', 'ES512'] as const // ECDSA with secp256k1 (ES256K) Edwards Curve DSA are not supported in browsers
export const ENC_ALGS = ['A128GCM', 'A256GCM'] as const // A192GCM is not supported in browsers
