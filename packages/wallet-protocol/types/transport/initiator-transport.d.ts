import { ConnectionString, Identity, WalletProtocol, PKEData, ProtocolPKEData, AuthData, MasterKey, ProtocolAuthData } from '../internal';
import { BaseTransport } from './transport';
import { Request } from './request';
export interface InitiatorOptions {
    host: string;
    id: Identity;
    l: number;
    getConnectionString: () => Promise<string>;
}
export declare abstract class InitiatorTransport<Req, Res> extends BaseTransport<Req, Res> {
    protected opts: InitiatorOptions;
    connString: ConnectionString | undefined;
    constructor(opts?: Partial<InitiatorOptions>);
    abstract sendRequest<T extends Request>(request: Request): Promise<T>;
    prepare(protocol: WalletProtocol, publicKey: string): Promise<PKEData>;
    publicKeyExchange(protocol: WalletProtocol, pkeData: PKEData): Promise<ProtocolPKEData>;
    authentication(protocol: WalletProtocol, authData: AuthData): Promise<ProtocolAuthData>;
    verification(protocol: WalletProtocol, masterKey: MasterKey): Promise<Uint8Array>;
    finish(protocol: WalletProtocol): void;
}
//# sourceMappingURL=initiator-transport.d.ts.map