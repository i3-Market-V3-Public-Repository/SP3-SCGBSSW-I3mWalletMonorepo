import { Resource, Identity, WalletMetadata, ToastOptions } from '@i3m/base-wallet'

import { PrivateSettings, createDefaultPrivateSettings, DialogData, ConnectData, CloudVaultData, toVaultState, PublicSettings } from '../internal'
import { WalletTask } from './tasks'
import type { ProviderData } from '@i3m/base-wallet'

export interface WalletMetadataMap {
  [packageName: string]: WalletMetadata
}

export interface ToastData extends ToastOptions {
  id: string
}

export interface SharedMemory {
  hasStore: boolean
  settings: {
    private: PrivateSettings
    public: PublicSettings
  }
  identities: {
    [did: string]: Identity | undefined
  }
  resources: {
    [id: string]: Resource | undefined
  }
  dialogs: {
    current?: string | undefined
    data: {
      [id: string]: DialogData
    }
  }
  toasts: ToastData[]
  walletsMetadata: WalletMetadataMap
  connectData: ConnectData
  cloudVaultData: CloudVaultData
  tasks: WalletTask[]
  defaultProviders: Record<string, ProviderData>
}

export function createDefaultSharedMemory (values?: Partial<SharedMemory>): SharedMemory {
  const priv: PrivateSettings = values?.settings as any ?? createDefaultPrivateSettings()
  const pub: PublicSettings = { version: '' }

  return {
    hasStore: false,
    settings: { private: priv, public: pub },
    identities: {},
    resources: {},
    dialogs: {
      current: undefined,
      data: {}
    },
    walletsMetadata: {},
    connectData: {
      walletProtocol: {}
    },
    toasts: [],
    tasks: [],
    cloudVaultData: {
      state: toVaultState('not-initialized'),
      syncing: false,
      blocking: false
    },
    defaultProviders: {},
    ...values
  }
}
