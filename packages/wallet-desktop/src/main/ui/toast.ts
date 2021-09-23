import { dialog } from 'electron'

interface ToastOptions {
  message: string
}

export const toast = {
  show (options: ToastOptions) {
    const { message } = options
    dialog.showMessageBoxSync({
      message
    })
  }
}
