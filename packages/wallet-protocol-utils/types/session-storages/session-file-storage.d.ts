import { SessionStorage, SessionFileStorageOptions } from '../types';
export declare class SessionFileStorage implements SessionStorage {
    filepath: string;
    private readonly password?;
    private salt?;
    private key?;
    initialized: Promise<void>;
    constructor(options?: SessionFileStorageOptions);
    private deriveKey;
    private init;
    private encryptJson;
    private decryptToJson;
    getSessionData(): Promise<any>;
    setSessionData(json: any): Promise<void>;
    clear(): Promise<void>;
}
export interface ScryptOptions {
    N?: number;
    r?: number;
    p?: number;
    maxmem?: number;
}
//# sourceMappingURL=session-file-storage.d.ts.map