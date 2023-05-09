
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
  tokenTTL?: number // in seconds
}

export const DEFAULT_TOKEN_TLL = 2419200 // 4 weeks

export interface Credentials {
  username: string
  password: string
}

export interface CloudVaultPrivateSettings {
  credentials?: Credentials
  uploadDebounceTime?: number

  // TODO: Not implemented yet
  retries?: number // number of retries
  retryDelay?: number // time between retries in milliseconds
}

export const DEFAULT_CLOUD_URL = 'https://my-vault-server.com:8000'
export const DEFAULT_UPLOAD_DEBOUNCE_TIME = 2000
export const DEFAULT_CLOUD_VAULT_RETRIES = 1 * 60 / 5 // Retry during one minute
export const DEFAULT_CLOUD_VAULT_RETRY_DELAY = 5000

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
      tokenTTL: DEFAULT_TOKEN_TLL // 4 weeks
    },
    developer: {
      enableDeveloperFunctions: false,
      enableDeveloperApi: false
    }
  }
}
