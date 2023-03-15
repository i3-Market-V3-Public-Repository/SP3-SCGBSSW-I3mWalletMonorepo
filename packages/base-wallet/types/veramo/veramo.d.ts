import { IDIDManager, IResolver, IKeyManager, IMessageHandler, TAgent } from '@veramo/core';
import { AbstractIdentifierProvider } from '@veramo/did-manager';
import { BaseWalletModel, Store } from '../app';
import { ISelectiveDisclosure } from '@veramo/selective-disclosure';
import { ICredentialIssuer } from '@veramo/credential-w3c';
import { KeyWallet } from '../keywallet';
type PluginMap = IDIDManager & IKeyManager & IResolver & IMessageHandler & ISelectiveDisclosure & ICredentialIssuer;
export interface ProviderData {
    network: string;
    rpcUrl?: string | string[];
    web3Provider?: object;
    ttl?: number;
    gas?: number;
    registry?: string;
}
export declare const DEFAULT_PROVIDER = "did:ethr:i3m";
export declare const DEFAULT_PROVIDERS_DATA: Record<string, ProviderData>;
export declare class Veramo<T extends BaseWalletModel = BaseWalletModel> {
    agent: TAgent<PluginMap>;
    providers: Record<string, AbstractIdentifierProvider>;
    defaultKms: string;
    providersData: Record<string, ProviderData>;
    constructor(store: Store<T>, keyWallet: KeyWallet, providersData: Record<string, ProviderData>);
    getProvider(name: string): AbstractIdentifierProvider;
}
export {};
//# sourceMappingURL=veramo.d.ts.map