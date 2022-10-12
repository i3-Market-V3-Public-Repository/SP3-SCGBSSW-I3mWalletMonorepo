import { Store, BaseWalletModel } from '../app';
import { CanBePromise } from '../utils';
export declare class TestStore implements Store<BaseWalletModel> {
    model: BaseWalletModel;
    constructor();
    private defaultModel;
    get(key: any, defaultValue?: any): any;
    set(key: string, value: unknown): CanBePromise<void>;
    has<Key extends 'accounts'>(key: Key): CanBePromise<boolean>;
    delete<Key extends 'accounts'>(key: Key): CanBePromise<void>;
    clear(): CanBePromise<void>;
}
//# sourceMappingURL=store.d.ts.map