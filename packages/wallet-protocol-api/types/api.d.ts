import { Session, HttpInitiatorTransport } from '@i3m/wallet-protocol';
import { WalletPaths } from '@i3m/wallet-desktop-openapi/types';
export declare class WalletApi {
    protected session: Session<HttpInitiatorTransport>;
    constructor(session: Session<HttpInitiatorTransport>);
    private executeQuery;
    getIdentites(queryParams?: WalletPaths.IdentityList.QueryParameters): Promise<WalletPaths.IdentityList.Responses.$200>;
}
//# sourceMappingURL=api.d.ts.map