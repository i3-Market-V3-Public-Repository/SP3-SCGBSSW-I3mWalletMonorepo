import { Transport, TransportRequest, TransportResponse } from '../internal';
import { MasterKey } from './master-key';
export declare class Session<T extends Transport> {
    protected transport: T;
    protected masterKey: MasterKey;
    protected code: Uint8Array;
    constructor(transport: T, masterKey: MasterKey, code: Uint8Array);
    send(request: TransportRequest<T>): Promise<TransportResponse<T>>;
    toJSON(): any;
    static fromJSON<T extends Transport>(transport: T, json: any): Promise<Session<T>>;
    static fromJSON<T extends Transport>(transportConstructor: new () => T, json: any): Promise<Session<T>>;
}
//# sourceMappingURL=session.d.ts.map