import { VaultState } from '@i3m/cloud-vault-client'

export interface CloudVaultData {
  state: VaultState
  syncing: boolean
  blocking: boolean
  registration?: {
    url: string
    username: string
  }
}
