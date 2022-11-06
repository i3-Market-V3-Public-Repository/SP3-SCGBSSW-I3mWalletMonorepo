import { WalletProtocol, ProtocolPKEData, AuthData, PKEData, ProtocolAuthData, MasterKey } from '../internal';
export interface Transport<Req = any, Res = any> {
    prepare: (protocol: WalletProtocol, publicKey: string) => Promise<PKEData>;
    publicKeyExchange: (protocol: WalletProtocol, pkeData: PKEData) => Promise<ProtocolPKEData>;
    authentication: (protocol: WalletProtocol, authData: AuthData) => Promise<ProtocolAuthData>;
    verification: (protocol: WalletProtocol, masterKey: MasterKey) => Promise<Uint8Array>;
    send: (masterKey: MasterKey, code: Uint8Array, request: Req) => Promise<Res>;
    finish: (protocol: WalletProtocol) => void;
}
export declare type TransportRequest<T> = T extends Transport<infer Req> ? Req : never;
export declare type TransportResponse<T> = T extends Transport<any, infer Res> ? Res : never;
export declare abstract class BaseTransport<Req, Res> implements Transport<Req, Res> {
    abstract prepare(protocol: WalletProtocol, publicKey: string): Promise<PKEData>;
    abstract publicKeyExchange(protocol: WalletProtocol, publicKey: PKEData): Promise<ProtocolPKEData>;
    abstract authentication(protocol: WalletProtocol, authData: AuthData): Promise<ProtocolAuthData>;
    abstract verification(protocol: WalletProtocol, masterKey: MasterKey): Promise<Uint8Array>;
    send(masterKey: MasterKey, code: Uint8Array, req: Req): Promise<Res>;
    finish(protocol: WalletProtocol): void;
}
//# sourceMappingURL=transport.d.ts.map