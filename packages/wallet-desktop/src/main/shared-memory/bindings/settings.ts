import { digest } from 'object-sha'
import { Locals, handleCanBePromise } from '@wallet/main/internal'

export const bindSettings = async (locals: Locals): Promise<void> => {
  const { sharedMemoryManager, storeManager } = locals
  const settings = storeManager.getStore('private-settings')

  const store = await settings.getStore()
  sharedMemoryManager.update((mem) => ({
    ...mem,
    settings: store
  }))

  sharedMemoryManager.on('change', (mem, oldMem) => {
    const newSha = digest(mem)
    const oldSha = digest(mem)
    if (oldSha !== newSha) {
      const promise = settings.set(mem.settings)
      handleCanBePromise(locals, promise)
    }
  })
}
