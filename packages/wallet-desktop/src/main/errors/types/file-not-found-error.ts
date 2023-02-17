
import { WalletDesktopError } from './wallet-desktop-error'

export class FileNotFoundError extends WalletDesktopError {
  constructor (file: string, critical: boolean = true) {
    const message = 'File not found!'
    super(message, {
      message,
      details: `The file '${file}' was not found.`,
      severity: 'error',
      critical
    })
  }
}
