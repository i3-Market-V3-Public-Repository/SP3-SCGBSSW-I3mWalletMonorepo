import { IDIDManager, IResolver, IKeyManager, IMessageHandler, TAgent } from '@veramo/core';
import { AbstractIdentifierProvider } from '@veramo/did-manager';
import { EthrDIDProvider } from '@veramo/did-provider-ethr';
import { BaseWalletModel, Store } from '../app';
import { ISelectiveDisclosure } from '@veramo/selective-disclosure';
import { ICredentialIssuer } from '@veramo/credential-w3c';
import { KeyWallet } from '../keywallet';
declare type PluginMap = IDIDManager & IKeyManager & IResolver & IMessageHandler & ISelectiveDisclosure & ICredentialIssuer;
export declare type ProviderData = Omit<ConstructorParameters<typeof EthrDIDProvider>[0], 'defaultKms'>;
export declare const DEFAULT_PROVIDER = "did:ethr:i3m";
export declare const DEFAULT_PROVIDERS_DATA: {
    'did:ethr:rinkeby': {
        network: string;
        rpcUrl: string;
    };
    'did:ethr:i3m': {
        network: string;
        rpcUrl: string;
    };
    'did:ethr:ganache': {
        network: string;
        rpcUrl: string;
    };
};
export default class Veramo<T extends BaseWalletModel = BaseWalletModel> {
    agent: TAgent<PluginMap>;
    providers: Record<string, AbstractIdentifierProvider>;
    defaultKms: string;
    providersData: Record<string, ProviderData>;
    constructor(store: Store<T>, keyWallet: KeyWallet, providersData: Record<string, ProviderData>);
    getProvider(name: string): AbstractIdentifierProvider;
}
export {};
//# sourceMappingURL=veramo.d.ts.map