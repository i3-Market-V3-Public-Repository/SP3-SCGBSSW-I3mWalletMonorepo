import { DEFAULT_UPLOAD_DEBOUNCE_TIME, storeChangedAction } from '@wallet/lib'
import { Epic, filterAction, handleErrorSync, isEncryptedStore, logger, WalletDesktopError } from '@wallet/main/internal'
import { interval } from 'rxjs'
import { debounce } from 'rxjs/operators'

export const uploadStoresEpic: Epic = (action$, locals, next) =>
  action$
    .pipe(
      filterAction(storeChangedAction),
      debounce(() => {
        const mem = locals.sharedMemoryManager.memory
        const $debounce = interval(mem.settings.cloud?.uploadDebounceTime ?? DEFAULT_UPLOAD_DEBOUNCE_TIME)
        return $debounce
      })
    ).subscribe((action) => {
      const [type, store] = action.payload
      const { cloudVaultManager: cvm } = locals

      logger.debug(`The store has been changed ${store.getPath()}`)
      if (isEncryptedStore(type)) {
        cvm.uploadVault().catch((err: Error) => {
          const fixedError = new WalletDesktopError('Could not upload stores', {
            severity: 'error',
            message: 'Upload store error',
            details: `Could not upload store due to '${err.message}'`
          })
          console.trace(err)
          handleErrorSync(locals, fixedError)
        })
      }
    })
