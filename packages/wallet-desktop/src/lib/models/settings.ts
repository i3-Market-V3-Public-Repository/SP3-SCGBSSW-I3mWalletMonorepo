
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

export interface Provider {
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

export interface AuthSettings {
  localAuth: string
  salt: string
}

export interface Settings {
  wallet: WalletSettings
  providers: Provider[]
  developer: DeveloperSettings
  connect: WalletConnectSettings
  auth?: AuthSettings
  secret?: JWK
}

export function createDefaultSettings (): Settings {
  return {
    wallet: {
      wallets: {},
      packages: ['@i3-market/sw-wallet']
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
