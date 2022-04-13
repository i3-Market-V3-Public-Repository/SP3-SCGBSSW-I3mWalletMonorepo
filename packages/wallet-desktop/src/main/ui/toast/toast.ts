
import { ToastOptions, ToastType, Toast } from '@i3m/base-wallet'
import { createDialogId, ToastData } from '@wallet/lib'
import { Locals } from '@wallet/main/internal'

const TOAST_TIMEOUT_MAP: Map<ToastType, number> = new Map([
  ['info', 2000],
  ['success', 4000],
  ['warning', 7000],
  ['error', 10000]
])

export class ToastManager implements Toast {
  constructor (protected locals: Locals) { }

  show (toastOptions: ToastOptions): void {
    const { windowManager, sharedMemoryManager } = this.locals
    const mainWindow = windowManager.openMainWindow()
    if (mainWindow === undefined) {
      throw new Error('No main window')
    }

    const toasts = sharedMemoryManager.memory.toasts
    const toast: ToastData = {
      id: createDialogId(),
      ...toastOptions
    }
    toasts.push(toast)

    sharedMemoryManager.update((mem) => ({
      ...mem,
      toasts
    }))

    mainWindow.flashFrame(false)
    mainWindow.flashFrame(true)

    const toastType = toast.type ?? 'info'
    const timeout = toastOptions.timeout ?? TOAST_TIMEOUT_MAP.get(toastType) ?? 0
    if (timeout !== 0) {
      setTimeout(() => {
        this.close(toast.id)
      }, timeout)
    }
  }

  close (toastId: string): void {
    const { sharedMemoryManager } = this.locals
    sharedMemoryManager.update((mem) => ({
      ...mem,
      toasts: mem.toasts.filter((toast) => toast.id !== toastId)
    }))
  }
}
