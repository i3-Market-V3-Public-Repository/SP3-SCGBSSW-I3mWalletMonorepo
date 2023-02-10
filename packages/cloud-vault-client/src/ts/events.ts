import { VaultError } from './error'

export type VaultEvent = { // eslint-disable-line @typescript-eslint/consistent-type-definitions
  connected: [
    timestamp?: number
  ]
  'logged-out': never
  'storage-updated': [
    timestamp: number // timestamp in milliseconds elapsed from EPOCH when the latest storage has been updated to the cloud.
  ]
  'storage-deleted': never // storage has been deleted in the cloud (by other client by the same user)
  'connection-error': [
    error: VaultError
  ]
}

export type VaultEventName = keyof VaultEvent
export type ArgsForEvent<T extends VaultEventName> = VaultEvent[T]
