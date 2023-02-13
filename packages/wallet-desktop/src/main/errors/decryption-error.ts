
import { WalletDesktopError } from './wallet-desktop-error'

export class DecryptionError extends WalletDesktopError {
  constructor (details: string, critical: boolean = true, resetSettings: boolean = true) {
    super(details, {
      message: 'Decryption error',
      details,
      severity: 'error',
      critical,
      resetSettings
    })
  }
}
