import { currentAuthAlgorithm, currentEncAlgorithm, currentStoreType, getCurrentAuthKeys, getCurrentEncKeys, LabeledTaskHandler, Locals, logger, MainContext, WalletDesktopError } from '@wallet/main/internal'

import { RuntimeScript } from '../runtime-script'

async function _migrate (ctx: MainContext, locals: Locals, task: LabeledTaskHandler): Promise<void> {
  const { versionManager } = locals
  task
    .setDetails(`Migrating your local data from version ${versionManager.settingsVersion} to version ${versionManager.softwareVersion}`)
    .update()

  const { keyCtx } = ctx
  if (keyCtx === undefined) {
    throw new WalletDesktopError('invalid context for this runtime!')
  }

  //
  const { sharedMemoryManager: shm, storeManager, keysManager } = locals
  const { public: publicSettings } = shm.memory.settings

  let migrateStores = false

  // Migrate store type
  const storeSettings = publicSettings.store
  if (storeSettings?.type !== currentStoreType) {
    logger.debug(`Migrate store type from ${storeSettings?.type ?? 'default'} to '${currentStoreType}'`)
    migrateStores = true

    // Set default StoreBuilder settings
    storeManager.defaultStoreSettings = { type: currentStoreType }

    shm.update((mem) => ({
      ...mem,
      settings: {
        ...mem.settings,
        public: {
          ...mem.settings.public,
          store: {
            ...mem.settings.public.store,
            type: currentStoreType
          }
        }
      }
    }))
  }

  const { auth, enc } = shm.memory.settings.public
  const authMigrationNeeded = auth?.algorithm !== currentAuthAlgorithm || await keysManager.authKeys.migrationNeeded()
  if (authMigrationNeeded) {
    logger.debug(`Migrate authentication keys from ${auth?.algorithm ?? 'default'} to '${currentAuthAlgorithm}'`)
    keyCtx.authKeys = await getCurrentAuthKeys()
    await keyCtx.authKeys.register(keyCtx)
    await keyCtx.authKeys.storeSettings(locals, keyCtx)
  }

  const encMigrationNeeded = enc?.algorithm !== currentEncAlgorithm || await keyCtx.encKeys.migrationNeeded()
  if (encMigrationNeeded) {
    migrateStores = true
    logger.debug(`Migrate encryption keys from '${enc?.algorithm ?? 'default'}' to '${currentEncAlgorithm}'`)

    keyCtx.encKeys = await getCurrentEncKeys()
    await keyCtx.encKeys.storeSettings(locals, keyCtx)
    await keyCtx.encKeys.prepareEncryption(keyCtx)
  }

  // Finish the migration, remove the key context!!
  keysManager.setKeyContext(keyCtx)
  delete ctx.keyCtx

  if (migrateStores) {
    logger.debug('Migrate stores data!')
    await storeManager.migrateStores()
  }

  await versionManager.migrateSettingsVersion()
}

export const migrate: RuntimeScript = async (ctx, locals) => {
  const { taskManager } = locals
  await taskManager.createTask('labeled', { title: 'Migrate', freezing: true }, async (task) => {
    await _migrate(ctx, locals, task)
  })
}
