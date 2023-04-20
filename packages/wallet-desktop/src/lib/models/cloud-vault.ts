import { VaultState } from '@i3m/cloud-vault-client'

export interface CloudVaultData {
  state: VaultState
  syncing: boolean
  loggingIn: boolean
  unsyncedChanges: boolean
  registration?: {
    url: string
    username: string
  }
}
