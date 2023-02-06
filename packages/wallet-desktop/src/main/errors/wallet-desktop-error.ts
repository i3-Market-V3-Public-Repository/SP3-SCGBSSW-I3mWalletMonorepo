import { ToastType } from '@i3m/base-wallet'
import { Locals } from '../internal'

export interface WalletDesktopOptions {
  critical: boolean
  severity: ToastType
  message: string
  details?: string
  timeout?: number
  resetSettings: boolean
}

export class WalletDesktopError extends Error {
  protected options: WalletDesktopOptions
  public readonly critical: boolean
  public readonly resetSettings: boolean
  public readonly details?: string

  /**
   * Errors handled by the wallet desktop application
   *
   * @param message The error message
   * @param critial If an error is critical will cause the application to shut down
   */
  constructor (message: string, options?: Partial<WalletDesktopOptions>) {
    super(message)
    this.options = Object.assign<WalletDesktopOptions, Partial<WalletDesktopOptions>>({
      critical: false,
      resetSettings: false,
      severity: 'warning',
      message: 'Something wrong happend...',
      details: 'Contact with the developers to fix this issue.'
    }, options ?? {})
    this.critical = this.options.critical
    this.details = this.options.details
    this.resetSettings = this.options.resetSettings
  }

  showToast (locals: Locals): void {
    locals.toast.show({
      message: this.options.message,
      details: this.options.details,
      type: this.options.severity,
      timeout: this.options.timeout
    })
  }

  async showDialog (locals: Locals): Promise<void> {
    await locals.dialog.confirmation({
      title: this.options.message,
      message: this.options.details,
      allowCancel: false,
      acceptMsg: 'Confirm',
      rejectMsg: ''
    })
  }
}
