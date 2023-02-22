import _ from 'lodash'
import { Locals, handleCanBePromise } from '@wallet/main/internal'

export const bindWithSettings = async (locals: Locals): Promise<void> => {
  const { sharedMemoryManager, storeManager } = locals
  const settings = storeManager.getStore('private-settings')

  const store = await settings.getStore()
  sharedMemoryManager.update((mem) => ({
    ...mem,
    settings: store
  }))

  sharedMemoryManager.on('change', ({ curr, prev, ctx }) => {
    if (ctx?.reason !== 'cloud-sync' && !_.isEqual(curr.settings, prev.settings)) {
      const promise = settings.set(curr.settings)
      handleCanBePromise(locals, promise)
    }
  })
}
