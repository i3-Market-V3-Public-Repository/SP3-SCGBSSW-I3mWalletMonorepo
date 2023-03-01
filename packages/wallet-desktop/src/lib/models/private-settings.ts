
import { ProviderData } from '@i3m/base-wallet'
import { JWK } from 'jose'
import { JSONObject } from './json-object'

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
}

export interface DeveloperSettings {
  enableDeveloperFunctions: boolean
  enableDeveloperApi: boolean
}

export interface WalletConnectSettings {
  enableTokenExpiration: boolean
  tokenTTL: number // in seconds
}

export interface Credentials {
  username: string
  password: string
}

export interface CloudVaultPrivateSettings {
  credentials?: Credentials
  url?: string
}

export const DEFAULT_CLOUD_URL = 'http://localhost:3000'

export const DEFAULT_WALLET_PACKAGES = [
  '@i3m/sw-wallet',
  '@i3m/bok-wallet'
]

export interface PrivateSettings {
  wallet: WalletSettings
  providers: Provider[]
  developer: DeveloperSettings
  connect: WalletConnectSettings
  cloud?: CloudVaultPrivateSettings
  secret?: JWK
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
