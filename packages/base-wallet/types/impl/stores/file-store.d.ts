import { Store, BaseWalletModel } from '../../app';
/**
 * A class that implements a storage for the wallet in a single file. The server wallet uses a file as storage.
 *
 * `filepath` is the path to the Wallet's storage file. If you are using a container it should be a path to a file that persists (like one in a volume)
 *
 * The wallet's storage-file can be encrypted for added security by passing an optional `password`.
 */
export declare class FileStore implements Store<BaseWalletModel> {
    filepath: string;
    password?: string;
    /**
     *
     * @param filepath an absolute path to the file that will be used to store wallet data
     * @param password if provided a key will be derived from the password and the store file will be encrypted
     */
    constructor(filepath: string, password?: string);
    private kdf;
    private init;
    private defaultModel;
    private getModel;
    private setModel;
    private encryptModel;
    private decryptModel;
    get(key: any, defaultValue?: any): Promise<any>;
    set(key: string, value: unknown): Promise<void>;
    has<Key extends 'accounts'>(key: Key): Promise<boolean>;
    delete<Key extends 'accounts'>(key: Key): Promise<void>;
    clear(): Promise<void>;
}
//# sourceMappingURL=file-store.d.ts.map