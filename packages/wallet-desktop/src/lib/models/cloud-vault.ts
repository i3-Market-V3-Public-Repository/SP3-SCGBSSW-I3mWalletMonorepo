
export type CloudVaultState = 'connected' | 'disconnected' | 'sync'

export interface CloudVaultData {
  state: CloudVaultState
}
