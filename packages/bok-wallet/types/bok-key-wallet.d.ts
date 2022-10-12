import { KeyLike, Dialog, Store, KeyWallet } from '@i3m/base-wallet';
import { BokWalletModel, Key } from './types';
export declare class BokKeyWallet implements KeyWallet {
    protected dialog: Dialog;
    protected store: Store<BokWalletModel>;
    constructor(dialog: Dialog, store: Store<BokWalletModel>);
    import(privateKeyHex: string): Promise<Key>;
    createAccountKeyPair(): Promise<string>;
    getPublicKey(kid: string): Promise<KeyLike>;
    signDigest(kid: string, messageDigest: Uint8Array): Promise<Uint8Array>;
    delete(kid: string): Promise<boolean>;
    wipe(): Promise<void>;
}
//# sourceMappingURL=bok-key-wallet.d.ts.map