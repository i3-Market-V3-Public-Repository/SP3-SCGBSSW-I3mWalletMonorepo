/// <reference types="node" />
import http from 'http';
import { Request } from '../request';
import { Response } from '../response';
export declare class HttpResponse<T extends Request> extends Response<T> {
    protected res: http.ServerResponse;
    constructor(res: http.ServerResponse);
    send(request: T): Promise<void>;
}
//# sourceMappingURL=http-response.d.ts.map