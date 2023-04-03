import { promises as fs } from 'fs'
import _ from 'lodash'

import { StoreSettings, WalletInfo } from '@wallet/lib'
import { EncryptionKeys, Locals, logger, MainContext, StoreFeatureOptions, WalletStoreOptions } from '@wallet/main/internal'

import { Store } from '@i3m/base-wallet'
import { getPath, loadStoreBuilder, StoreOptions } from './builders'
import { StoreOptionsBuilder } from './migration'

export class StoreBuilder {
  storeInfo: StoreSettings

  constructor (protected ctx: MainContext, protected locals: Locals) {
    this.storeInfo = { type: 'electron-store' }
  }

  public async buildWalletStoreOptions (wallet: WalletInfo, opts: StoreFeatureOptions | undefined, encKeys?: EncryptionKeys): Promise<WalletStoreOptions> {
    const { keysManager } = this.locals
    const name = _.get(opts, 'name', 'wallet')
    const storePath = _.get(opts, 'storePath', this.ctx.args.config)
    const encryptionEnabled: boolean = _.get(opts, 'encryption.enabled', false)
    const storeId = wallet.store

    const storeOpts: WalletStoreOptions = {
      defaults: {
        start: new Date(),
        identities: {},
        resources: {}
      },
      name: `${name}.${storeId}`,
      cwd: storePath,
      fileExtension: encryptionEnabled ? 'enc.json' : 'json'
    }

    if (encryptionEnabled) {
      storeOpts.encryptionKey = await keysManager.computeWalletKey(wallet.store, encKeys)
    }

    return storeOpts
  }

  public async buildOptionsBuilder <T extends Record<string, any>>(optionsBuilder: StoreOptionsBuilder<T>, migrate = true): Promise<[store: Store<T>, options: StoreOptions<T>]> {
    const { to, needed } = this.ctx.storeMigrationProxy
    if (needed) {
      if (migrate) {
        return await this.migrateStore<T>(optionsBuilder)
      } else {
        const options = await optionsBuilder({
          cwd: to.cwd,
          encKeys: to.encKeys
        })
        return await this.buildStore<T>({ ...options, storeType: to.storeType })
      }
    } else {
      const options = await optionsBuilder({
        cwd: this.ctx.args.config,
        encKeys: this.locals.keysManager.encKeys
      })
      return await this.buildStore<T>({ ...options, storeType: to.storeType })
    }
  }

  public async buildStore <T extends Record<string, any> = Record<string, unknown>>(options?: Partial<StoreOptions<T>>): Promise<[store: Store<T>, options: StoreOptions<T>]> {
    const fixedOptions = Object.assign({}, {
      cwd: this.ctx.args.config,
      fileExtension: 'json',
      name: 'config',
      storeType: this.storeInfo.type
    }, options)
    const builder = loadStoreBuilder<T>(fixedOptions.storeType)
    const path = getPath(this.ctx, this.locals, options)
    logger.debug(`Loading store on '${path}'`)

    // TODO: Check if the format is corret. If not fix corrupted data
    return [await builder.build(this.ctx, this.locals, fixedOptions), fixedOptions]
  }

  public async migrateStore <T extends Record<string, any>>(optionsBuilder: StoreOptionsBuilder<T>): Promise<[store: Store<T>, options: StoreOptions<T>]> {
    const { from, to } = this.ctx.storeMigrationProxy

    // Read old data
    const oldOptions = await optionsBuilder(from)
    const filepath = getPath(this.ctx, this.locals, oldOptions)
    const [oldStore] = await this.buildStore({ ...oldOptions, storeType: from.storeType })
    const storeData = await oldStore.getStore()

    // Remove old store
    await fs.rm(filepath)

    // Create new store
    const newOptions = await optionsBuilder(to)
    const [newStore, options] = await this.buildStore({ ...newOptions, storeType: to.storeType })
    await newStore.set(storeData)

    return [newStore, options]
  }
}
