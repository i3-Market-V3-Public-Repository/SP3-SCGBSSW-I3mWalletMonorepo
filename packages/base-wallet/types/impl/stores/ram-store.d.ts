import { Store } from '../../app';
import { CanBePromise } from '../../utils';
/**
 * A class that implements a storage in RAM to be used by a wallet
 */
export declare class RamStore<T extends Record<string, any> = Record<string, unknown>> implements Store<T> {
    protected defaultModel: T;
    model: T;
    constructor(defaultModel: T);
    get(key: any, defaultValue?: any): any;
    set(keyOrStore?: any, value?: any): CanBePromise<void>;
    has<Key extends 'accounts'>(key: Key): CanBePromise<boolean>;
    delete<Key extends 'accounts'>(key: Key): CanBePromise<void>;
    clear(): CanBePromise<void>;
    getStore(): CanBePromise<T>;
    getPath(): string;
}
//# sourceMappingURL=ram-store.d.ts.map