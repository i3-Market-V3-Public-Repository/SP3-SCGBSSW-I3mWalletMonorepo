
import { WalletDesktopError } from './wallet-desktop-error'

export class FormatError extends WalletDesktopError {
  constructor (details: string, critical: boolean = true, resetSettings: boolean = true) {
    super(details, {
      message: 'Format error',
      details,
      severity: 'error',
      critical,
      resetSettings
    })
  }
}
