
export type CloudVaultState = 'connected' | 'disconnected' | 'sync' | 'not synced'

export interface CloudVaultData {
  state: CloudVaultState
}
