import { VaultError } from './error'

export const VAULT_STATE = {
  NOT_INITIALIZED: 0 as const,
  INITIALIZED: 1 as const,
  LOGGED_IN: 2 as const,
  CONNECTED: 3 as const
} as const

export type VaultState = typeof VAULT_STATE['NOT_INITIALIZED'] | typeof VAULT_STATE['INITIALIZED'] | typeof VAULT_STATE['LOGGED_IN'] | typeof VAULT_STATE['CONNECTED']

export function stateFromError (currentState: VaultState, error: unknown): VaultState {
  const vaultError = VaultError.from(error)
  switch (vaultError.message) {
    case 'invalid-credentials':
    case 'unauthorized':
      return VAULT_STATE.INITIALIZED
    case 'sse-connection-error':
      return (currentState >= VAULT_STATE.LOGGED_IN) ? VAULT_STATE.LOGGED_IN : VAULT_STATE.INITIALIZED
    default:
      return currentState
  }
}
