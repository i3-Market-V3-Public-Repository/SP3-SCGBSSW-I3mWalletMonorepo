import { Session, Transport, WalletProtocol } from '@i3m/wallet-protocol';
import { Subject } from 'rxjs';
import { SessionStorage, SessionManagerOpts, SessionManagerOptions } from './types';
export declare class SessionManager<T extends Transport = Transport> {
    session: Session<T> | undefined;
    $session: Subject<Session<T> | undefined>;
    initialized: Promise<void>;
    protected storage: SessionStorage;
    protected protocol: WalletProtocol<T>;
    constructor(options: SessionManagerOpts<T>);
    private init;
    get hasSession(): boolean;
    fetch: Session<T>['send'];
    createIfNotExists(): Promise<Session<T>>;
    removeSession(): Promise<void>;
    setSession(session?: Session<T>): Promise<void>;
    loadSession(): Promise<void>;
}
export declare class LocalSessionManager<T extends Transport = Transport> extends SessionManager<T> {
    protected protocol: WalletProtocol<T>;
    constructor(protocol: WalletProtocol<T>, options?: Partial<SessionManagerOptions>);
}
//# sourceMappingURL=session-manager.d.ts.map