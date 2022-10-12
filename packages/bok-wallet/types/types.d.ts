import { WalletOptionsSettings, BaseWalletModel } from '@i3m/base-wallet';
export declare type KeyType = 'Secp256k1';
export interface Key {
    kid: string;
    type: KeyType;
    publicKeyHex: string;
    privateKeyHex: string;
}
export interface BokWalletModel extends BaseWalletModel {
    keys: {
        [kid: string]: Key;
    };
}
export interface BokWalletOptions extends WalletOptionsSettings<BokWalletModel> {
}
//# sourceMappingURL=types.d.ts.map