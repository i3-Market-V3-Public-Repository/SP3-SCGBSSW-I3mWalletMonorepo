import { Resource, Identity, WalletMetadata, ToastOptions } from '@i3m/base-wallet'
import { Settings, createDefaultSettings, DialogData, ConnectData } from '../internal'

export interface WalletMetadataMap {
  [packageName: string]: WalletMetadata
}

export interface ToastData extends ToastOptions {
  id: string
}

export interface SharedMemory {
  hasStore: boolean
  settings: Settings
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
}

export function createDefaultSharedMemory (values?: Partial<SharedMemory>): SharedMemory {
  const settings = values?.settings ?? createDefaultSettings()

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

    ...values
  }
}
