/// <reference types="node" />
import http from 'http';
import { ResponderTransport, ResponderOptions } from '../responder-transport';
export interface HttpResponderOptions extends ResponderOptions {
    rpcUrl: string;
}
export declare class HttpResponderTransport extends ResponderTransport<http.IncomingMessage, never> {
    readonly rpcUrl: string;
    protected listeners: http.RequestListener[];
    constructor(opts?: Partial<HttpResponderOptions>);
    protected readRequestBody(req: http.IncomingMessage): Promise<string>;
    protected dispatchProtocolMessage(req: http.IncomingMessage, res: http.ServerResponse): Promise<void>;
    protected dispatchEncryptedMessage(req: http.IncomingMessage, res: http.ServerResponse, authentication: string): Promise<void>;
    dispatchRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void>;
    private callListeners;
    use(listener: http.RequestListener): void;
}
//# sourceMappingURL=http-responder.d.ts.map