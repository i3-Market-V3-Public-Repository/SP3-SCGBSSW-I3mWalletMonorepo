
import { JWK } from 'jose'
import { JSONObject } from './json-object'
import { ProviderData } from '@i3m/base-wallet'
import { AuthSettings, EncSettings } from './key-algorithms'

export interface WalletInfo {
  name: string
  package: string
  store: string
  args: JSONObject
}

export interface WalletSettings {
  current?: string // Module name of the current wallet
  wallets: {
    [walletName: string]: WalletInfo
  }
  packages: string[]
}

export interface Provider extends ProviderData {
  name: string
  provider: string
}

export interface DeveloperSettings {
  enableDeveloperFunctions: boolean
  enableDeveloperApi: boolean
}

export interface WalletConnectSettings {
  enableTokenExpiration: boolean
  tokenTTL: number // in seconds
}

export interface CloudVaultSettings {
  token: string
}

export const DEFAULT_WALLET_PACKAGES = [
  '@i3m/sw-wallet',
  '@i3m/bok-wallet'
]

export interface PrivateSettings {
  wallet: WalletSettings
  providers: Provider[]
  developer: DeveloperSettings
  connect: WalletConnectSettings
  cloud?: CloudVaultSettings
  secret?: JWK
}

export type StoreType = 'electron-store' | 'file-store'

export interface StoreSettings {
  type?: StoreType
}

export interface PublicSettings {
  version: string
  auth?: AuthSettings
  enc?: EncSettings
  store?: StoreSettings
}

export function createDefaultPrivateSettings (): PrivateSettings {
  return {
    wallet: {
      wallets: {},
      packages: DEFAULT_WALLET_PACKAGES
    },
    providers: [],
    connect: {
      enableTokenExpiration: true,
      tokenTTL: 2419200 // 4 weeks
    },
    developer: {
      enableDeveloperFunctions: false,
      enableDeveloperApi: false
    }
  }
}
