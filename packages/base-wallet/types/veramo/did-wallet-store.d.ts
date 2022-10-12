import { IIdentifier } from '@veramo/core';
import { AbstractDIDStore } from '@veramo/did-manager';
import { BaseWalletModel, Store } from '../app';
export default class DIDWalletStore<T extends BaseWalletModel> extends AbstractDIDStore {
    protected store: Store<T>;
    constructor(store: Store<T>);
    import(args: IIdentifier): Promise<boolean>;
    get(args: {
        did: string;
    }): Promise<IIdentifier>;
    get(args: {
        alias: string;
        provider: string;
    }): Promise<IIdentifier>;
    delete(args: {
        did: string;
    }): Promise<boolean>;
    list(args: {
        alias?: string | undefined;
        provider?: string | undefined;
    }): Promise<IIdentifier[]>;
}
//# sourceMappingURL=did-wallet-store.d.ts.map