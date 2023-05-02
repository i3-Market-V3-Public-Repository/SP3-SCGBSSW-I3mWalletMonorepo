import _ from 'lodash'
import { Locals, handleCanBePromise, MainContext } from '@wallet/main/internal'
import { PrivateSettings, PublicSettings } from '@wallet/lib'

export const bindWithSettings = async (ctx: MainContext, locals: Locals): Promise<void> => {
  const { sharedMemoryManager: shm, storeManager } = locals
  const privStore = storeManager.getStore('private-settings')
  const pubStore = storeManager.getStore('public-settings')

  async function updatePrivateSettingsIfChanged (curr: PrivateSettings, prev?: PrivateSettings): Promise<void> {
    if (!_.isEqual(curr, prev)) {
      await privStore.set(curr)
    }
  }

  async function updatePublicSettingsIfChanged (curr: PublicSettings, prev?: PublicSettings): Promise<void> {
    if (!_.isEqual(curr, prev)) {
      await pubStore.set(curr)
    }
  }

  // Update stores
  await updatePrivateSettingsIfChanged(shm.memory.settings.private, ctx.initialPrivateSettings)
  await updatePublicSettingsIfChanged(shm.memory.settings.public, ctx.initialPublicSettings)

  shm.on('change', ({ curr, prev, ctx }) => {
    const modifiers = ctx?.modifiers ?? {}
    if (modifiers['no-settings-update'] !== true) {
      let promise = updatePrivateSettingsIfChanged(curr.settings.private, prev.settings.private)
      handleCanBePromise(locals, promise)

      promise = updatePublicSettingsIfChanged(curr.settings.public, prev.settings.public)
      handleCanBePromise(locals, promise)
    }
  })
}
