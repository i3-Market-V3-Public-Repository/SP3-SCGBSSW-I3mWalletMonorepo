import { WalletPaths } from '@i3m/wallet-desktop-openapi/types';
import { ApiExecutor } from '../types';
export declare class ProviderInfoApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    get(): Promise<WalletPaths.ProviderinfoGet.Responses.$200>;
}
//# sourceMappingURL=providerinfo.d.ts.map