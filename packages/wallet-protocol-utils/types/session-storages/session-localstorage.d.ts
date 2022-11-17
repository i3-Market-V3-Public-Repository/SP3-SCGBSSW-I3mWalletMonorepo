import { SessionStorage, SessionLocalStorageOptions } from '../types';
export declare class SessionLocalStorage implements SessionStorage {
    protected key: string;
    constructor(options?: SessionLocalStorageOptions);
    getSessionData(): Promise<any>;
    setSessionData(json: any): Promise<void>;
    clear(): Promise<void>;
}
//# sourceMappingURL=session-localstorage.d.ts.map