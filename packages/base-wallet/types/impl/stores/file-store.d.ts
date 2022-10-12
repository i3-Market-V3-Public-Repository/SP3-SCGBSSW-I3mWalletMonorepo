import { Store, BaseWalletModel } from '../../app';
/**
 * A class that implements a storage in a file to be used by a wallet
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