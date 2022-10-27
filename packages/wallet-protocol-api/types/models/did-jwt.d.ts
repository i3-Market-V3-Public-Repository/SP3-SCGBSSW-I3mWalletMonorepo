import { WalletPaths } from '@i3m/wallet-desktop-openapi/types';
import { ApiExecutor } from '../types';
export declare class DidJwtApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    verify(body: WalletPaths.DidJwtVerify.RequestBody): Promise<WalletPaths.DidJwtVerify.Responses.$200>;
}
//# sourceMappingURL=did-jwt.d.ts.map