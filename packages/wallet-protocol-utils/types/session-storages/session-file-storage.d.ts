import { SessionStorage, SessionFileStorageOptions } from '../types';
export declare class SessionFileStorage implements SessionStorage {
    filepath: string;
    password?: string;
    initialized: Promise<boolean>;
    constructor(options?: SessionFileStorageOptions);
    private init;
    private kdf;
    private encryptJson;
    private decryptToJson;
    getSessionData(): Promise<any>;
    setSessionData(json: any): Promise<void>;
    clear(): Promise<void>;
}
//# sourceMappingURL=session-file-storage.d.ts.map