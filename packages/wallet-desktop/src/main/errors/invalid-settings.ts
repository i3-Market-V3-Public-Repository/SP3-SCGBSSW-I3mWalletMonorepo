import { WalletDesktopError } from './wallet-desktop-error'

export class InvalidSettingsError extends WalletDesktopError {
  constructor (message: string) {
    super(message, {
      critical: true,
      message: 'Invalid settings',
      details: message
    })
  }
}
