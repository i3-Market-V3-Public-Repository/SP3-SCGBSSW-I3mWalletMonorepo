import { WalletPaths } from '@i3m/wallet-desktop-openapi/types';
import { ApiExecutor } from '../types';
export declare class TransactionApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    deploy(body: WalletPaths.TransactionDeploy.RequestBody): Promise<WalletPaths.TransactionDeploy.Responses.$200>;
}
//# sourceMappingURL=transaction.d.ts.map