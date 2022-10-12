import { Store, BaseWalletModel } from '../../app';
import { CanBePromise } from '../../utils';
/**
 * A class that implements a storage in RAM to be used by a wallet
 */
export declare class RamStore implements Store<BaseWalletModel> {
    model: BaseWalletModel;
    constructor();
    private defaultModel;
    get(key: any, defaultValue?: any): any;
    set(key: string, value: unknown): CanBePromise<void>;
    has<Key extends 'accounts'>(key: Key): CanBePromise<boolean>;
    delete<Key extends 'accounts'>(key: Key): CanBePromise<void>;
    clear(): CanBePromise<void>;
}
//# sourceMappingURL=ram-store.d.ts.map