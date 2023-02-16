import { Resource, Identity, WalletMetadata, ToastOptions } from '@i3m/base-wallet'
import { PrivateSettings, createDefaultPrivateSettings, DialogData, ConnectData, CloudVaultData } from '../internal'
import { WalletTask } from './tasks'

export interface WalletMetadataMap {
  [packageName: string]: WalletMetadata
}

export interface ToastData extends ToastOptions {
  id: string
}

export interface SharedMemory {
  hasStore: boolean
  settings: PrivateSettings
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
}

export function createDefaultSharedMemory (values?: Partial<SharedMemory>): SharedMemory {
  const settings = values?.settings ?? createDefaultPrivateSettings()

  return {
    hasStore: false,
    settings,
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
      state: 'not-logged'
    },
    ...values
  }
}
