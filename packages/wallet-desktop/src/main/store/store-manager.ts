import { promises as fs, existsSync } from 'fs'

import { Store } from '@i3m/base-wallet'
import { PublicSettings, StoreSettings, StoreType } from '@wallet/lib'
import { FormatError, Locals, logger, MainContext, paths } from '@wallet/main/internal'
import { StoreOptions, loadStoreBuilder, currentStoreType, getPath } from './builders'

export class StoreManager {
  storeInfo: StoreSettings

  constructor (protected ctx: MainContext, protected locals: Locals) {
    this.storeInfo = { type: 'electron-store' }
  }

  async initialize (): Promise<void> {
    const { publicConfig } = paths(this.ctx)
    try {
      const settingsBuffer = (await fs.readFile(publicConfig)).toString()
      const publicSettings: PublicSettings = JSON.parse(settingsBuffer)

      this.storeInfo = publicSettings.store ?? { type: 'electron-store' }
    } catch (e: any) {
      if (e instanceof SyntaxError) {
        throw new FormatError('Inconsistent file format')
      }
      if (e.code === 'ENOENT') {
        logger.info('Public settings file is not created yet')
      } else {
        throw e
      }
    }

    if (this.storeInfo.type !== currentStoreType) {
      this.ctx.storeMigrationProxy.from.storeType = this.storeInfo.type
      this.ctx.storeMigrationProxy.to.storeType = currentStoreType
      this.ctx.storeMigrationProxy.migrations.push(async (to) => {
        this.storeInfo.type = to.storeType
        await this.locals.publicSettings.set('store', { type: to.storeType })
      })
    }
  }

  public async getWalletUuids (): Promise<string[]> {
    const walletUuids: string[] = []
    const dir = await fs.opendir(this.ctx.settingsPath)
    for await (const dirent of dir) {
      if (dirent.name.startsWith('wallet.')) {
        const walletUuid = dirent.name.split('.')[1]
        walletUuids.push(walletUuid)
      }
    }
    return walletUuids
  }

  private async migrateStore (options: Partial<StoreOptions<any>>, newOptions: Partial<StoreOptions<any>>): Promise<void> {
    const { from, to } = this.ctx.storeMigrationProxy

    // Read old data
    const filepath = getPath(this.ctx, this.locals, options)
    if (!existsSync(filepath)) {
      return
    }

    const oldStore = await this.buildStore(options, from.storeType)
    const storeData = await oldStore.getStore()

    // Remove old store
    await fs.rm(filepath)

    // Create new store
    const newStore = await this.buildStore(newOptions, to.storeType)
    await newStore.set(storeData)
  }

  public async migrate (): Promise<void> {
    const { from, to, needed, migrations } = this.ctx.storeMigrationProxy
    if (needed) {
      const { keysManager } = this.locals
      const oldSettingsKey = await keysManager.computeSettingsKey(from.encKeys)
      const newSettingsKey = await keysManager.computeSettingsKey(to.encKeys)
      await this.migrateStore({
        fileExtension: 'enc.json',
        encryptionKey: oldSettingsKey
      }, {
        fileExtension: 'enc.json',
        encryptionKey: newSettingsKey
      })

      const walletUuids = await this.getWalletUuids()
      for (const uuid of walletUuids) {
        const oldWalletKey = await keysManager.computeWalletKey(uuid, from.encKeys)
        const newWalletKey = await keysManager.computeWalletKey(uuid, to.encKeys)
        await this.migrateStore({
          name: `wallet.${uuid}`,
          fileExtension: 'enc.json',
          encryptionKey: oldWalletKey
        }, {
          name: `wallet.${uuid}`,
          fileExtension: 'enc.json',
          encryptionKey: newWalletKey
        })
      }
    }

    for (const migration of migrations) {
      await migration(to)
    }
  }

  public async buildStore <T extends Record<string, any> = Record<string, unknown>>(options?: Partial<StoreOptions<T>>, storeType?: StoreType): Promise<Store<T>> {
    const fixedOptions = Object.assign({}, {
      cwd: this.ctx.settingsPath,
      fileExtension: 'json',
      name: 'config'
    }, options)
    const builder = loadStoreBuilder<T>(storeType ?? this.storeInfo.type)
    const path = getPath(this.ctx, this.locals, options)
    logger.debug(`Loading store on '${path}'`)
    try {
      return await builder.build(this.ctx, this.locals, fixedOptions)
    } catch (e) {
      if (e instanceof SyntaxError) {
        throw new FormatError(`Inconsistent format on file '${path}'`)
      }
      throw e
    }
  }
}
