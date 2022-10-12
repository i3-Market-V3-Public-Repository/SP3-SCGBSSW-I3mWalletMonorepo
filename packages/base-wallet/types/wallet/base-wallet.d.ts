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
    getIdentities(): Promise<BaseWalletModel['identities']>;
    identityList(queryParameters: WalletPaths.IdentityList.QueryParameters): Promise<WalletPaths.IdentityList.Responses.$200>;
    identityCreate(requestBody: WalletPaths.IdentityCreate.RequestBody): Promise<WalletPaths.IdentityCreate.Responses.$201>;
    identitySelect(queryParameters: WalletPaths.IdentitySelect.QueryParameters): Promise<WalletPaths.IdentitySelect.Responses.$200>;
    identitySign(pathParameters: WalletPaths.IdentitySign.PathParameters, requestBody: WalletPaths.IdentitySign.RequestBody): Promise<WalletPaths.IdentitySign.Responses.$200>;
    identityInfo(pathParameters: WalletPaths.IdentityInfo.PathParameters): Promise<WalletPaths.IdentityInfo.Responses.$200>;
    identityDeployTransaction(pathParameters: WalletPaths.IdentityDeployTransaction.PathParameters, requestBody: WalletComponents.Schemas.Transaction): Promise<WalletComponents.Schemas.Receipt>;
    getResources(): Promise<BaseWalletModel['resources']>;
    resourceList(): Promise<WalletPaths.ResourceList.Responses.$200>;
    deleteResource(id: string): Promise<void>;
    deleteIdentity(did: string): Promise<void>;
    resourceCreate(requestBody: WalletPaths.ResourceCreate.RequestBody): Promise<WalletPaths.ResourceCreate.Responses.$201>;
    selectiveDisclosure(pathParameters: WalletPaths.SelectiveDisclosure.PathParameters): Promise<WalletPaths.SelectiveDisclosure.Responses.$200>;
    transactionDeploy(requestBody: WalletComponents.Schemas.SignedTransaction): Promise<WalletPaths.TransactionDeploy.Responses.$200>;
    didJwtVerify(requestBody: WalletPaths.DidJwtVerify.RequestBody): Promise<WalletPaths.DidJwtVerify.Responses.$200>;
    providerinfo(): Promise<WalletPaths.Providerinfo.Responses.$200>;
}
export {};
//# sourceMappingURL=base-wallet.d.ts.map