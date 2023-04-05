import { VaultState } from './vault-state'

export type VaultEvent = { // eslint-disable-line @typescript-eslint/consistent-type-definitions
  'state-changed': [
    state: VaultState
  ]
  'empty-storage': never
  'storage-updated': [
    timestamp: number // timestamp in milliseconds elapsed from EPOCH when the latest storage has been updated to the cloud.
  ]
  'storage-deleted': never // storage has been deleted in the cloud (by other client by the same user)
  'sync-start': [
    startTime: number
  ]
  'sync-stop': [
    startTime: number,
    stopTime: number
  ]
}

export type VaultEventName = keyof VaultEvent
export type ArgsForEvent<T extends VaultEventName> = VaultEvent[T]
