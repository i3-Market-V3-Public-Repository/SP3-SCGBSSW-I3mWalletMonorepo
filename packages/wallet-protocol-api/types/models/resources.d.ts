import { WalletPaths } from '@i3m/wallet-desktop-openapi/types';
import { ApiExecutor } from '../types';
export declare class ResourcesApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    list(options?: WalletPaths.ResourceList.QueryParameters): Promise<WalletPaths.ResourceList.Responses.$200>;
    create(body: WalletPaths.ResourceCreate.RequestBody): Promise<WalletPaths.ResourceCreate.Responses.$201>;
}
//# sourceMappingURL=resources.d.ts.map