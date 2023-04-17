import { Session, HttpInitiatorTransport } from '@i3m/wallet-protocol';
import { WalletPaths } from '@i3m/wallet-desktop-openapi/types';

type Params = Record<string, string> | undefined;
type Body = any;
interface ApiMethod {
    path: string;
    method: string;
    headers?: Record<string, string>;
}
interface ApiExecutor {
    executeQuery: <T>(api: ApiMethod, pathParams: Params, queryParams: Params, bodyObject: Body) => Promise<T>;
}

declare class IdentitiesApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    list(queryParams?: WalletPaths.IdentityList.QueryParameters): Promise<WalletPaths.IdentityList.Responses.$200>;
    select(queryParams?: WalletPaths.IdentitySelect.QueryParameters): Promise<WalletPaths.IdentitySelect.Responses.$200>;
    create(body: WalletPaths.IdentityCreate.RequestBody): Promise<WalletPaths.IdentityCreate.Responses.$201>;
    sign(pathParams: WalletPaths.IdentitySign.PathParameters, body: WalletPaths.IdentitySign.RequestBody): Promise<WalletPaths.IdentitySign.Responses.$200>;
    info(pathParams: WalletPaths.IdentityInfo.PathParameters): Promise<WalletPaths.IdentityInfo.Responses.$200>;
    deployTransaction(pathParams: WalletPaths.IdentityDeployTransaction.PathParameters, body: WalletPaths.IdentityDeployTransaction.RequestBody): Promise<WalletPaths.IdentityDeployTransaction.Responses.$200>;
}

declare class ResourcesApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    list(options?: WalletPaths.ResourceList.QueryParameters): Promise<WalletPaths.ResourceList.Responses.$200>;
    create(body: WalletPaths.ResourceCreate.RequestBody): Promise<WalletPaths.ResourceCreate.Responses.$201>;
}

declare class DisclosureApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    disclose(pathParams: WalletPaths.SelectiveDisclosure.PathParameters): Promise<WalletPaths.SelectiveDisclosure.Responses.$200>;
}

declare class TransactionApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    deploy(body: WalletPaths.TransactionDeploy.RequestBody): Promise<WalletPaths.TransactionDeploy.Responses.$200>;
}

declare class DidJwtApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    verify(body: WalletPaths.DidJwtVerify.RequestBody): Promise<WalletPaths.DidJwtVerify.Responses.$200>;
}

declare class ProviderInfoApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    get(): Promise<WalletPaths.ProviderinfoGet.Responses.$200>;
}

declare class WalletApi implements ApiExecutor {
    protected session: Session<HttpInitiatorTransport>;
    identities: IdentitiesApi;
    transaction: TransactionApi;
    resources: ResourcesApi;
    disclosure: DisclosureApi;
    didJwt: DidJwtApi;
    providerinfo: ProviderInfoApi;
    constructor(session: Session<HttpInitiatorTransport>);
    executeQuery<T>(api: ApiMethod, pathParams: Params, queryParams: Params, bodyObject: Body): Promise<T>;
}

declare class WalletApiError extends Error {
    code: number;
    body: any;
    constructor(message: string, code: number, body: any);
}

export { WalletApi, WalletApiError };
