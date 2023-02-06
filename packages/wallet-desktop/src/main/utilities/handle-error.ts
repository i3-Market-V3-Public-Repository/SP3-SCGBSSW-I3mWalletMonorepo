import { app } from 'electron'

import { Locals, logger, WalletDesktopError } from '@wallet/main/internal'
import { CanBePromise } from '@i3m/base-wallet'

export function handleError (locals: Locals): Parameters<Promise<void>['catch']> {
  return [async (err) => {
    if (err instanceof Error) {
      logger.error(err.stack)
    } else {
      logger.error(err)
    }

    if (err instanceof WalletDesktopError) {
      if (err.resetSettings) {
        // await locals.dialog.confirmation({
        //   title: err.message,
        //   message: [err.message, 'The '].join('\n\n')
        // })
      }

      if (err.critical) {
        await err.showDialog(locals)
        return app.quit()
      } else {
        err.showToast(locals)
      }
    }
  }]
}

export function handleCanBePromise<T> (locals: Locals, promise: CanBePromise<T>): void {
  if (promise instanceof Promise) {
    promise.catch(...handleError(locals))
  }
}
