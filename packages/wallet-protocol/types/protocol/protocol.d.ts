import { Transport, ECDH, ConnectionString } from '../internal';
import { EventEmitter } from './event-emitter';
import { ProtocolAuthData, ProtocolPKEData } from './state';
import { MasterKey } from './master-key';
import { Session } from './session';
export declare class WalletProtocol<T extends Transport = Transport> extends EventEmitter {
    transport: T;
    constructor(transport: T);
    computeR(ra: Uint8Array, rb: Uint8Array): Promise<Uint8Array>;
    computeNx(): Promise<Uint8Array>;
    computeCx(pkeData: ProtocolPKEData, nx: Uint8Array, r: Uint8Array): Promise<Uint8Array>;
    validateAuthData(fullPkeData: ProtocolPKEData, fullAuthData: ProtocolAuthData): Promise<void>;
    computeMasterKey(ecdh: ECDH, fullPkeData: ProtocolPKEData, fullAuthData: ProtocolAuthData): Promise<MasterKey>;
    run(): Promise<Session<T>>;
    on(event: 'connString', listener: (connString: ConnectionString) => void): this;
    on(event: 'masterKey', listener: (masterKey: MasterKey) => void): this;
    on(event: 'finished', listener: () => void): this;
    emit(event: 'connString', connString: ConnectionString): boolean;
    emit(event: 'masterKey', masterKey: MasterKey): boolean;
    emit(event: 'finished'): boolean;
}
//# sourceMappingURL=protocol.d.ts.map