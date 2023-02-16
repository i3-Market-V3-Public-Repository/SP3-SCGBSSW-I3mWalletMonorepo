
export type CloudVaultState = 'in-progress' | 'complete' | 'not-logged'

export interface CloudVaultData {
  state: CloudVaultState
}
