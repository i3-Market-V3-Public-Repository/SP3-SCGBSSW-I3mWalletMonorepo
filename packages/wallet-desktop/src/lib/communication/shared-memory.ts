import { Resource, Identity, WalletMetadata } from '@i3-market/base-wallet'
import { Settings, createDefaultSettings, DialogData } from '../internal'

export interface WalletMetadataMap {
  [packageName: string]: WalletMetadata
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
  walletsMetadata: WalletMetadataMap
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

    ...values
  }
}
