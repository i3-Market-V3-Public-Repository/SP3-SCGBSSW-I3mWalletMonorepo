import { WalletDesktopError } from './wallet-desktop-error'

export class StartFeatureError extends WalletDesktopError {
  constructor (message: string, exit = false) {
    super(message, {
      critical: exit,
      message
    })
  }
}
