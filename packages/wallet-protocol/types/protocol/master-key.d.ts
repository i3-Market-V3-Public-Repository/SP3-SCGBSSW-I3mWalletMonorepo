import { Cipher } from '../internal';
import { Identity } from './state';
export declare class MasterKey {
    readonly port: number;
    readonly from: Identity;
    readonly to: Identity;
    readonly na: Uint8Array;
    readonly nb: Uint8Array;
    protected secret: Uint8Array;
    protected cipher: Cipher;
    protected decipher: Cipher;
    constructor(port: number, from: Identity, to: Identity, na: Uint8Array, nb: Uint8Array, secret: Uint8Array, encryptKey: Uint8Array, decryptKey: Uint8Array);
    encrypt(message: Uint8Array): Promise<Uint8Array>;
    decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
    toJSON(): any;
    fromHash(): Promise<string>;
    toHash(): Promise<string>;
    static fromSecret(port: number, from: Identity, to: Identity, na: Uint8Array, nb: Uint8Array, secret: Uint8Array): Promise<MasterKey>;
    static fromJSON(data: any): Promise<MasterKey>;
}
//# sourceMappingURL=master-key.d.ts.map