import _ from 'lodash'
import { Store } from '@i3m/base-wallet'
import { Locals, handleCanBePromise, MainContext, getUndefinedKeys, WalletDesktopError } from '@wallet/main/internal'

export const bindWithSettings = async (ctx: MainContext, locals: Locals): Promise<void> => {
  const { sharedMemoryManager: shm, storeManager } = locals
  const privStore = storeManager.getStore('private-settings')
  const pubStore = storeManager.getStore('public-settings')

  async function updateSettingsIfChanged <T extends Record<any, any>> (store: Store<T>, curr: T, prev?: T): Promise<void> {
    if (!_.isEqual(curr, prev)) {
      const undefinedKeys = getUndefinedKeys(curr)
      for (const key of undefinedKeys) {
        if (!_.unset(curr, key)) {
          throw new WalletDesktopError(`could not delete property ${key} from ${store.getPath()}`, {
            message: 'Store error',
            details: `Could not delete property ${key} from ${store.getPath()}`,
            severity: 'error'
          })
        }
        await pubStore.delete(key)
      }

      await store.set(curr)
    }
  }

  // Update stores
  await updateSettingsIfChanged(privStore, shm.memory.settings.private, ctx.initialPrivateSettings)
  await updateSettingsIfChanged(pubStore, shm.memory.settings.public, ctx.initialPublicSettings)

  shm.on('change', ({ curr, prev, ctx }) => {
    const modifiers = ctx?.modifiers ?? {}
    if (modifiers['no-settings-update'] !== true) {
      let promise = updateSettingsIfChanged(privStore, curr.settings.private, prev.settings.private)
      handleCanBePromise(locals, promise)

      promise = updateSettingsIfChanged(pubStore, curr.settings.public, prev.settings.public)
      handleCanBePromise(locals, promise)
    }
  })
}
