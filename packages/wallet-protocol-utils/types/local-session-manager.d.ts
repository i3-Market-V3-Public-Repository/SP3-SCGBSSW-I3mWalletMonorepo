import { WalletProtocol, Session, Transport } from '@i3m/wallet-protocol';
import { Subject } from 'rxjs';
export interface SessionManagerOptions {
    localStorageKey: string;
}
export declare class LocalSessionManager<T extends Transport = Transport> {
    protected protocol: WalletProtocol<T>;
    protected opts: SessionManagerOptions;
    session: Session<T> | undefined;
    $session: Subject<Session<T> | undefined>;
    constructor(protocol: WalletProtocol<T>, options?: Partial<SessionManagerOptions>);
    get hasSession(): boolean;
    fetch: Session<T>['send'];
    createIfNotExists(): Promise<Session<T>>;
    removeSession(): void;
    setSession(session?: Session<T>): void;
    loadSession(): Promise<void>;
}
