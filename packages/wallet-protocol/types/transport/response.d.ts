import { Request } from './request';
export declare abstract class Response<T extends Request = Request> {
    abstract send(request: T): Promise<void>;
}
//# sourceMappingURL=response.d.ts.map