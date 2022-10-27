import { WalletPaths } from '@i3m/wallet-desktop-openapi/types';
import { ApiExecutor } from '../types';
export declare class IdentitiesApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    list(queryParams?: WalletPaths.IdentityList.QueryParameters): Promise<WalletPaths.IdentityList.Responses.$200>;
    select(queryParams?: WalletPaths.IdentitySelect.QueryParameters): Promise<WalletPaths.IdentitySelect.Responses.$200>;
    create(body: WalletPaths.IdentityCreate.RequestBody): Promise<WalletPaths.IdentityCreate.Responses.$201>;
    sign(pathParams: WalletPaths.IdentitySign.PathParameters, body: WalletPaths.IdentitySign.RequestBody): Promise<WalletPaths.IdentitySign.Responses.$200>;
    info(pathParams: WalletPaths.IdentityInfo.PathParameters): Promise<WalletPaths.IdentityInfo.Responses.$200>;
    deployTransaction(pathParams: WalletPaths.IdentityDeployTransaction.PathParameters, body: WalletPaths.IdentityDeployTransaction.RequestBody): Promise<WalletPaths.IdentityDeployTransaction.Responses.$200>;
}
//# sourceMappingURL=identities.d.ts.map