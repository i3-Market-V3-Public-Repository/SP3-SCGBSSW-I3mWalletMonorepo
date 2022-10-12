import { IKey } from '@veramo/core';
import { AbstractKeyStore } from '@veramo/key-manager';
import { KeyWallet } from '../keywallet';
export default class KeyWalletStore extends AbstractKeyStore {
    protected keyWallet: KeyWallet;
    constructor(keyWallet: KeyWallet);
    import(args: IKey): Promise<boolean>;
    get(args: {
        kid: string;
    }): Promise<IKey>;
    delete(args: {
        kid: string;
    }): Promise<boolean>;
}
//# sourceMappingURL=key-wallet-store.d.ts.map