// Core interfaces
import { createAgent, IDIDManager, IResolver, IKeyManager, IMessageHandler, TAgent } from '@veramo/core'

// Core identity manager plugin
import { DIDManager } from '@veramo/did-manager'

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

type PluginMap =
  IDIDManager & IKeyManager & IResolver & IMessageHandler &
  ISelectiveDisclosure & ICredentialIssuer

export const DEFAULT_PROVIDER = 'did:ethr:rinkeby'

export default class Veramo<T extends BaseWalletModel = BaseWalletModel> {
  public agent: TAgent<PluginMap>

  constructor (store: Store<T>, keyWallet: KeyWallet) {
    const defaultKms = 'keyWallet'
    const RINKEBY_PROVIDER_DATA = {
      defaultKms,
      network: 'rinkeby',
      rpcUrl: 'https://rinkeby.infura.io/ethr-did'
    }

    const I3M_PROVIDER_DATA = {
      defaultKms,
      network: 'i3m',
      rpcUrl: 'http://95.211.3.250:8545'
    }

    const GANACHE_PROVIDER_DATA = {
      defaultKms,
      network: 'ganache',
      rpcUrl: 'http://127.0.0.1:7545'
    }

    const resolver = new Resolver({
      ...ethrDidResolver({
        networks: [RINKEBY_PROVIDER_DATA, I3M_PROVIDER_DATA, GANACHE_PROVIDER_DATA]
          .map(({ network, rpcUrl }) => ({
            name: network,
            rpcUrl
          }))
      }),
      ...webDidResolver()
    })

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
          providers: {
            'did:ethr:rinkeby': new EthrDIDProvider(RINKEBY_PROVIDER_DATA),
            'did:ethr:i3m': new EthrDIDProvider(I3M_PROVIDER_DATA),
            'did:ethr:ganache': new EthrDIDProvider(GANACHE_PROVIDER_DATA),
            'did:web': new WebDIDProvider({ defaultKms })
          }
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
}
