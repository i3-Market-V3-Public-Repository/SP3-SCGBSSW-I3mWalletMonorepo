import Debug from 'debug'

import {
  Toast,
  ToastOptions
} from '../app'

const debug = Debug('base-wallet:TestDialog')

export class TestToast implements Toast {
  show (toast: ToastOptions): void {
    debug('Show message:', toast.message)
  }

  close (toastId: string): void {
    debug('Close toast', toastId)
  }
}
