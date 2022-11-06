/// <reference types="node" />
import { ConnectionString, Identity, WalletProtocol, PKEData, Subject, AuthData, MasterKey, ProtocolAuthData, ProtocolPKEData, CodeGenerator } from '../internal';
import { BaseTransport } from './transport';
import { Request } from './request';
import { Response } from './response';
export interface ResponderOptions {
    port: number;
    timeout: number;
    id: Identity;
    l: number;
    codeGenerator: CodeGenerator;
}
interface SubjectData<T extends Request = Request, S extends Request = Request> {
    req: T;
    res: Response<S>;
}
export declare abstract class ResponderTransport<Req, Res> extends BaseTransport<Req, Res> {
    protected opts: ResponderOptions;
    protected rpcSubject: Subject<SubjectData>;
    protected lastPairing: NodeJS.Timeout | undefined;
    connString: ConnectionString | undefined;
    constructor(opts?: Partial<ResponderOptions>);
    pairing(protocol: WalletProtocol, port: number, timeout: number): Promise<void>;
    stopPairing(): void;
    get isPairing(): boolean;
    get port(): number;
    get timeout(): number;
    prepare(protocol: WalletProtocol, publicKey: string): Promise<PKEData>;
    waitRequest<M extends Request['method'], T extends (Request & {
        method: M;
    })>(method: M): Promise<SubjectData<T>>;
    publicKeyExchange(protocol: WalletProtocol, pkeData: PKEData): Promise<ProtocolPKEData>;
    authentication(protocol: WalletProtocol, authData: AuthData): Promise<ProtocolAuthData>;
    verification(protocol: WalletProtocol, masterKey: MasterKey): Promise<Uint8Array>;
    finish(protocol: WalletProtocol): void;
}
export {};
//# sourceMappingURL=responder-transport.d.ts.map