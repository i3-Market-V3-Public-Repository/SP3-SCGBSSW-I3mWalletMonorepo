import { WalletPaths } from '@i3m/wallet-desktop-openapi/types';
import { ApiExecutor } from '../types';
export declare class DisclosureApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    disclose(pathParams: WalletPaths.SelectiveDisclosure.PathParameters): Promise<WalletPaths.SelectiveDisclosure.Responses.$200>;
}
//# sourceMappingURL=disclosure.d.ts.map