
import { WalletDesktopError } from './wallet-desktop-error'

export class NoConnectionError extends WalletDesktopError {
  constructor (message: string) {
    super(message, {
      message: 'Checking for updates...',
      details: 'Error checking for updates. Are you connected to the Internet?',
      severity: 'warning',
      timeout: 0
    })
  }
}
