import _ from 'lodash'
import { Locals, handleCanBePromise } from '@wallet/main/internal'

export const bindWithSettings = async (locals: Locals): Promise<void> => {
  const { sharedMemoryManager, storeManager } = locals
  const settings = storeManager.getStore('private-settings')
  const store = await settings.getStore()

  // Update private settings
  sharedMemoryManager.update((mem) => ({
    ...mem,
    settings: store
  }))

  sharedMemoryManager.on('change', ({ curr, prev, ctx }) => {
    const modifiers = ctx?.modifiers ?? {}
    if (modifiers['no-settings-update'] !== true && !_.isEqual(curr.settings, prev.settings)) {
      const promise = settings.set(curr.settings)
      handleCanBePromise(locals, promise)
    }
  })
}
