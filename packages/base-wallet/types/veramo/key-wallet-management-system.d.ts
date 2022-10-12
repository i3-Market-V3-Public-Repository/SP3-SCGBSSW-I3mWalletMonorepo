import { TKeyType, IKey } from '@veramo/core';
import { AbstractKeyManagementSystem } from '@veramo/key-manager';
import { KeyWallet } from '../keywallet';
export default class KeyWalletManagementSystem extends AbstractKeyManagementSystem {
    protected keyWallet: KeyWallet;
    constructor(keyWallet: KeyWallet);
    createKey(args: {
        type: TKeyType;
        meta?: any;
    }): Promise<Omit<IKey, 'kms'>>;
    deleteKey(args: {
        kid: string;
    }): Promise<boolean>;
    encryptJWE(args: {
        key: IKey;
        to: Omit<IKey, 'kms'>;
        data: string;
    }): Promise<string>;
    decryptJWE(args: {
        key: IKey;
        data: string;
    }): Promise<string>;
    signJWT(args: {
        key: IKey;
        data: string | Uint8Array;
    }): Promise<string>;
    signEthTX(args: {
        key: IKey;
        transaction: any;
    }): Promise<string>;
}
//# sourceMappingURL=key-wallet-management-system.d.ts.map