import { Session, HttpInitiatorTransport } from '@i3m/wallet-protocol';
import { DisclosureApi, IdentitiesApi, ResourcesApi, TransactionApi } from './models';
import { ApiExecutor, Params, Body, ApiMethod } from './types';
export declare class WalletApi implements ApiExecutor {
    protected session: Session<HttpInitiatorTransport>;
    identities: IdentitiesApi;
    transaction: TransactionApi;
    resources: ResourcesApi;
    disclosure: DisclosureApi;
    constructor(session: Session<HttpInitiatorTransport>);
    executeQuery<T>(api: ApiMethod, pathParams: Params, queryParams: Params, bodyObject: Body): Promise<T>;
}
