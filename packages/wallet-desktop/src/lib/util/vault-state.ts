import { VaultState } from '@i3m/cloud-vault-client'

export type VaultStateString = 'connected' | 'logged-in' | 'initialized' | 'not-initialized'

export function toVaultState (str: VaultStateString): VaultState {
  switch (str) {
    case 'connected':
      return 3

    case 'logged-in':
      return 2

    case 'initialized':
      return 1

    case 'not-initialized':
      return 0
  }
}
