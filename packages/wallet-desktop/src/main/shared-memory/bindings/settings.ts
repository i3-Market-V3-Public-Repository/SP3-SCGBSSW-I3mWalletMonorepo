import _ from 'lodash'
import { Locals, handleCanBePromise } from '@wallet/main/internal'

export const bindWithSettings = async (locals: Locals): Promise<void> => {
  const { sharedMemoryManager: shm, storeManager } = locals

  // Update stores
  const privStore = storeManager.getStore('private-settings')
  await privStore.set(shm.memory.settings.private)

  const pubStore = storeManager.getStore('public-settings')
  await pubStore.set(shm.memory.settings.public)

  // shm.update((mem) => ({
  //   ...mem,
  //   settings: {
  //     private: privData,
  //     public: pubData
  //   }
  // }))

  shm.on('change', ({ curr, prev, ctx }) => {
    const modifiers = ctx?.modifiers ?? {}
    if (modifiers['no-settings-update'] !== true) {
      if (!_.isEqual(curr.settings.private, prev.settings.private)) {
        const promise = privStore.set(curr.settings.private)
        handleCanBePromise(locals, promise)
      }
      if (!_.isEqual(curr.settings.public, prev.settings.public)) {
        const promise = pubStore.set(curr.settings.public)
        handleCanBePromise(locals, promise)
      }
    }
  })
}
