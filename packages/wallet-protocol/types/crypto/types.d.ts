export declare class BaseECDH {
    generateKeys(): Promise<void>;
    getPublicKey(): Promise<string>;
    deriveBits(publicKeyHex: string): Promise<Uint8Array>;
}
export declare class BaseRandom {
    randomFill(buffer: Uint8Array, start: number, size: number): Promise<void>;
    randomFillBits(buffer: Uint8Array, start: number, size: number): Promise<void>;
}
export declare type CipherAlgorithms = 'aes-256-gcm';
export declare class BaseCipher {
    readonly algorithm: CipherAlgorithms;
    readonly key: Uint8Array;
    constructor(algorithm: CipherAlgorithms, key: Uint8Array);
    encrypt(payload: Uint8Array): Promise<Uint8Array>;
    decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
}
export declare type HashAlgorithms = 'sha256';
export declare class BaseDigest {
    digest(algorithm: HashAlgorithms, input: Uint8Array): Promise<Uint8Array>;
}
//# sourceMappingURL=types.d.ts.map