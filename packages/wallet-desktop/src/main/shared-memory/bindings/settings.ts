import _ from 'lodash'
import { Locals, handleCanBePromise } from '@wallet/main/internal'

export const bindSettings = async (locals: Locals): Promise<void> => {
  const { sharedMemoryManager, storeManager } = locals
  const settings = storeManager.getStore('private-settings')

  const store = await settings.getStore()
  sharedMemoryManager.update((mem) => ({
    ...mem,
    settings: store
  }))

  sharedMemoryManager.on('change', (newMem, oldMem) => {
    if (!_.isEqual(newMem.settings, oldMem.settings)) {
      const promise = settings.set(newMem.settings)
      handleCanBePromise(locals, promise)
    }
  })
}
