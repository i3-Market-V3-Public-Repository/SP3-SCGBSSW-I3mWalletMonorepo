// Core interfaces
import { createAgent, IDIDManager, IResolver, IKeyManager, IMessageHandler, TAgent } from '@veramo/core'

// Core identity manager plugin
import { AbstractIdentifierProvider, DIDManager } from '@veramo/did-manager'

// Ethr did identity provider
import { EthrDIDProvider } from '@veramo/did-provider-ethr'

// Web did identity provider
import { WebDIDProvider } from '@veramo/did-provider-web'

// Core key manager plugin
import { KeyManager } from '@veramo/key-manager'
import { BaseWalletModel, Store } from '../app'

//
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver as ethrDidResolver } from 'ethr-did-resolver'
import { getResolver as webDidResolver } from 'web-did-resolver'

// SDR
import { ISelectiveDisclosure, SelectiveDisclosure, SdrMessageHandler } from '@veramo/selective-disclosure'
import { MessageHandler } from '@veramo/message-handler'
import { JwtMessageHandler } from '@veramo/did-jwt'
import { W3cMessageHandler, CredentialIssuer, ICredentialIssuer } from '@veramo/credential-w3c'

import { KeyWallet } from '../keywallet'
import DIDWalletStore from './did-wallet-store'
import KeyWalletManagementSystem from './key-wallet-management-system'
import KeyWalletStore from './key-wallet-store'
import { WalletError } from '../errors'

type PluginMap =
  IDIDManager & IKeyManager & IResolver & IMessageHandler &
  ISelectiveDisclosure & ICredentialIssuer

export type ProviderData = Omit<ConstructorParameters<typeof EthrDIDProvider>[0], 'defaultKms'>

export const DEFAULT_PROVIDER = 'did:ethr:i3m'
export const DEFAULT_PROVIDERS_DATA = {
  'did:ethr:rinkeby': {
    network: 'rinkeby',
    rpcUrl: 'https://rpc.ankr.com/eth_rinkeby'
  },
  'did:ethr:i3m': {
    network: 'i3m',
    rpcUrl: 'http://95.211.3.250:8545'
  },
  'did:ethr:ganache': {
    network: 'ganache',
    rpcUrl: 'http://127.0.0.1:7545'
  }
}

export default class Veramo<T extends BaseWalletModel = BaseWalletModel> {
  public agent: TAgent<PluginMap>
  public providers: Record<string, AbstractIdentifierProvider>
  public defaultKms = 'keyWallet'
  public providersData: Record<string, ProviderData>

  constructor (store: Store<T>, keyWallet: KeyWallet, providersData: Record<string, ProviderData>) {
    this.providersData = providersData

    const resolver = new Resolver({
      ...ethrDidResolver({
        networks: Object.values(this.providersData)
          .map(({ network, rpcUrl }) => ({
            name: network,
            rpcUrl
          }))
      }),
      ...webDidResolver()
    })

    this.providers = {
      'did:web': new WebDIDProvider({ defaultKms: this.defaultKms })
    }
    for (const [key, provider] of Object.entries(this.providersData)) {
      this.providers[key] = new EthrDIDProvider({
        defaultKms: this.defaultKms,
        ...provider
      })
    }

    this.agent = createAgent<PluginMap>({
      plugins: [
        new KeyManager({
          store: new KeyWalletStore(keyWallet),
          kms: {
            keyWallet: new KeyWalletManagementSystem(keyWallet)
          }
        }),
        new DIDManager({
          store: new DIDWalletStore<T>(store),
          defaultProvider: DEFAULT_PROVIDER,
          providers: this.providers
        }),
        new CredentialIssuer(),
        new SelectiveDisclosure(),
        // new DataStore(dbConnection),
        // new DataStoreORM(dbConnection),
        new MessageHandler({
          messageHandlers: [
            new JwtMessageHandler(),
            new SdrMessageHandler(),
            new W3cMessageHandler()
          ]
        }),
        new DIDResolverPlugin({
          resolver
        })
      ]
    })
  }

  getProvider (name: string): AbstractIdentifierProvider {
    const provider = this.providers[name]
    if (provider === undefined) throw new WalletError('Identifier provider does not exist: ' + name)
    return provider
  }
}
