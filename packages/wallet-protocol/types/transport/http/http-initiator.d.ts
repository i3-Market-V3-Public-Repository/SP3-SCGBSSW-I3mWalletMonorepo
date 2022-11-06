import { MasterKey } from '../../internal';
import { InitiatorTransport } from '../initiator-transport';
import { Request } from '../request';
export interface HttpRequest {
    url: string;
    init?: RequestInit;
}
export interface HttpResponse {
    status: number;
    body: string;
}
export declare class HttpInitiatorTransport extends InitiatorTransport<HttpRequest, HttpResponse> {
    buildRpcUrl(port: number): string;
    baseSend(port: number, httpReq: RequestInit): Promise<HttpResponse>;
    sendRequest<T extends Request>(request: Request): Promise<T>;
    send(masterKey: MasterKey, code: Uint8Array, req: HttpRequest): Promise<HttpResponse>;
}
//# sourceMappingURL=http-initiator.d.ts.map