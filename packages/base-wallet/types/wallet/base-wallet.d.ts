import { WalletComponents, WalletPaths } from '@i3m/wallet-desktop-openapi/types';
import { IMessage, VerifiablePresentation } from '@veramo/core';
import { BaseWalletModel, Dialog, Identity, Store, Toast } from '../app';
import { KeyWallet } from '../keywallet';
import { ResourceValidator } from '../resource';
import Veramo, { ProviderData } from '../veramo';
import { Wallet } from './wallet';
import { WalletFunctionMetadata } from './wallet-metadata';
import { WalletOptions } from './wallet-options';
interface SelectIdentityOptions {
    reason?: string;
}
interface TransactionOptions {
    transaction?: string;
    notifyUser?: boolean;
}
declare type ResourceMap = BaseWalletModel['resources'];
export declare class BaseWallet<Options extends WalletOptions<Model>, Model extends BaseWalletModel = BaseWalletModel> implements Wallet {
    dialog: Dialog;
    store: Store<Model>;
    toast: Toast;
    veramo: Veramo<Model>;
    protected keyWallet: KeyWallet;
    protected resourceValidator: ResourceValidator;
    protected provider: string;
    protected providersData: Record<string, ProviderData>;
    constructor(opts: Options);
    executeTransaction(options?: TransactionOptions): Promise<void>;
    queryBalance(): Promise<void>;
    createTransaction(): Promise<void>;
    wipe(): Promise<void>;
    selectIdentity(options?: SelectIdentityOptions): Promise<Identity>;
    selectCredentialsForSdr(sdrMessage: IMessage): Promise<VerifiablePresentation | undefined>;
    getKeyWallet<T extends KeyWallet>(): T;
    call(functionMetadata: WalletFunctionMetadata): Promise<void>;
    /**
     * Gets a list of identities managed by this wallet
     * @returns
     */
    getIdentities(): Promise<BaseWalletModel['identities']>;
    /**
     * Returns a list of DIDs managed by this wallet
     *
     * @param queryParameters. You can filter by alias.
     * @returns
     */
    identityList(queryParameters: WalletPaths.IdentityList.QueryParameters): Promise<WalletPaths.IdentityList.Responses.$200>;
    /**
     * Creates an identity
     * @param requestBody
     * @returns the DID of the created identity
     */
    identityCreate(requestBody: WalletPaths.IdentityCreate.RequestBody): Promise<WalletPaths.IdentityCreate.Responses.$201>;
    identitySelect(queryParameters: WalletPaths.IdentitySelect.QueryParameters): Promise<WalletPaths.IdentitySelect.Responses.$200>;
    /**
     * Signs using the identity set in pathParameters. Currently suporting RAW signatures of base64url-encoded data, arbritrary JSON objects (it returns a JWT); and transactions for the DLT.
     * @param pathParameters
     * @param requestBody
     * @returns
     */
    identitySign(pathParameters: WalletPaths.IdentitySign.PathParameters, requestBody: WalletPaths.IdentitySign.RequestBody): Promise<WalletPaths.IdentitySign.Responses.$200>;
    /**
     * Returns info regarding an identity. It includes DLT addresses bounded to the identity
     *
     * @param pathParameters
     * @returns
     */
    identityInfo(pathParameters: WalletPaths.IdentityInfo.PathParameters): Promise<WalletPaths.IdentityInfo.Responses.$200>;
    identityDeployTransaction(pathParameters: WalletPaths.IdentityDeployTransaction.PathParameters, requestBody: WalletComponents.Schemas.Transaction): Promise<WalletComponents.Schemas.Receipt>;
    /**
     * Get resources stored in the wallet's vault. It is the place where to find stored verfiable credentials, agreements, non-repudiable proofs.
     * @returns
     */
    getResources(): Promise<ResourceMap>;
    private getResource;
    private setResource;
    /**
     * Gets a list of resources stored in the wallet's vault.
     * @returns
     */
    resourceList(query: WalletPaths.ResourceList.QueryParameters): Promise<WalletPaths.ResourceList.Responses.$200>;
    /**
     * Deletes a given resource and all its children
     * @param id
     */
    deleteResource(id: string, requestConfirmation?: boolean): Promise<void>;
    /**
     * Deletes a given identity (DID) and all its associated resources
     * @param did
     */
    deleteIdentity(did: string): Promise<void>;
    /**
     * Securely stores in the wallet a new resource.
     *
     * @param requestBody
     * @returns and identifier of the created resource
     */
    resourceCreate(requestBody: WalletPaths.ResourceCreate.RequestBody): Promise<WalletPaths.ResourceCreate.Responses.$201>;
    /**
     * Initiates the flow of choosing which credentials to present after a selective disclosure request.
     * @param pathParameters
     * @returns
     */
    selectiveDisclosure(pathParameters: WalletPaths.SelectiveDisclosure.PathParameters): Promise<WalletPaths.SelectiveDisclosure.Responses.$200>;
    /**
     * Deploys a transaction to the connected DLT
     * @param requestBody
     * @returns
     */
    transactionDeploy(requestBody: WalletComponents.Schemas.SignedTransaction): Promise<WalletPaths.TransactionDeploy.Responses.$200>;
    /**
     * Verifies a JWT resolving the public key from the signer DID (no other kind of signer supported) and optionally check values for expected payload claims.
     *
     * The Wallet only supports the 'ES256K1' algorithm.
     *
     * Useful to verify JWT created by another wallet instance.
     * @param requestBody
     * @returns
     */
    didJwtVerify(requestBody: WalletPaths.DidJwtVerify.RequestBody): Promise<WalletPaths.DidJwtVerify.Responses.$200>;
    /**
     * Retrieves information regarding the current connection to the DLT.
     * @returns
     */
    providerinfoGet(): Promise<WalletPaths.ProviderinfoGet.Responses.$200>;
}
export {};
//# sourceMappingURL=base-wallet.d.ts.map