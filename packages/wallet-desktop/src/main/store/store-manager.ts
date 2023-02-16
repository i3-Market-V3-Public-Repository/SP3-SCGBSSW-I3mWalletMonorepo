import { app } from 'electron'
import { existsSync, promises as fs, rmSync } from 'fs'
import _ from 'lodash'
import path from 'path'

import { Store } from '@i3m/base-wallet'
import {
  createDefaultPrivateSettings,
  StoreSettings,
  StoreType,
  WalletInfo
} from '@wallet/lib'
import {
  EncryptionKeys,
  handleError,
  Locals,
  logger,
  MainContext,
  PublicSettingsOptions,
  softwareVersion,
  StoreFeatureOptions, WalletDesktopError,
  WalletStoreOptions
} from '@wallet/main/internal'
import { currentStoreType, getPath, loadStoreBuilder, StoreOptions } from './builders'
import { StoreBuilder } from './migration'
import { StoreClass, StoreClasses, StoreModels } from './store-class'
import { StoreBundleData, StoreMetadata, StoresBundle } from './store-bundle'

const DEFAULT_STORE_SETTINGS: StoreSettings = {
  type: 'electron-store'
}

const buildWalletStoreOptions = async (wallet: WalletInfo, opts: StoreFeatureOptions | undefined, locals: Locals, encKeys?: EncryptionKeys): Promise<WalletStoreOptions> => {
  const { keysManager } = locals
  const name = _.get(opts, 'name', 'wallet')
  const storePath = _.get(opts, 'storePath', path.resolve(app.getPath('userData')))
  const encryptionEnabled: boolean = _.get(opts, 'encryption.enabled', false)
  const storeId = wallet.store

  const storeOpts: WalletStoreOptions = {
    name: `${name}.${storeId}`,
    cwd: storePath,
    fileExtension: encryptionEnabled ? 'enc.json' : 'json'
  }

  if (encryptionEnabled) {
    storeOpts.encryptionKey = await keysManager.computeWalletKey(wallet.store, encKeys)
  }

  return storeOpts
}

export class StoreManager {
  storeInfo: StoreSettings
  stores: Record<string, Store<any>>

  constructor (protected ctx: MainContext, protected locals: Locals) {
    this.storeInfo = { type: 'electron-store' }
    this.stores = {}
  }

  public async migrate (): Promise<void> {
    const { to, migrations } = this.ctx.storeMigrationProxy

    for (const migration of migrations) {
      await migration(to)
    }
  }

  public async loadPublicStores (): Promise<void> {
    const options: PublicSettingsOptions = {
      defaults: { version: softwareVersion(this.locals) }
    }

    // NOTE: Public settings must always be not encrypted and using the electorn store.
    // This guarantees compatibilities with future versions!
    const publicSettings = await this.buildStore(options, 'electron-store')
    this.setStore(publicSettings, 'public-settings')

    this.storeInfo = await publicSettings.get('store') ?? DEFAULT_STORE_SETTINGS
    if (this.storeInfo.type !== currentStoreType) {
      this.ctx.storeMigrationProxy.from.storeType = this.storeInfo.type
      this.ctx.storeMigrationProxy.to.storeType = currentStoreType
      this.ctx.storeMigrationProxy.migrations.push(async (to) => {
        this.storeInfo.type = to.storeType
        await publicSettings.set('store', { type: to.storeType })
      })
    }
  }

  public async loadEncryptedStores (): Promise<void> {
    const { keysManager, walletFactory } = this.locals
    const publicSettings = this.getStore('public-settings')
    const publicSettingsValues = await publicSettings.getStore()

    await this.executeStoreBuilder({
      id: this.getStoreId('private-settings'),
      options: async (migration) => ({
        defaults: Object.assign({}, createDefaultPrivateSettings(), publicSettingsValues),
        encryptionKey: await keysManager.computeSettingsKey(migration.encKeys),
        fileExtension: 'enc.json'
      })
    })

    const privateSettings = this.getStore('private-settings')
    const walletSettings = await privateSettings.get('wallet')
    const walletStoreBuilders: Array<StoreBuilder<any>> = Object
      .values(walletSettings.wallets)
      .map((wallet) => ({
        wallet,
        storeFeature: walletFactory.getWalletFeature<StoreFeatureOptions>(wallet.package, 'store')
      }))
      .filter(({ storeFeature }) => storeFeature !== undefined)
      .map(({ wallet, storeFeature }) => ({
        id: this.getStoreId('wallet', wallet.name),
        options: async (migration) => (
          await buildWalletStoreOptions(wallet, storeFeature?.opts, this.locals, migration.encKeys)
        )
      }))

    for (const builder of walletStoreBuilders) {
      await this.executeStoreBuilder(builder)
    }
  }

  public async buildWalletStore (walletName: string): Promise<void> {
    const { walletFactory } = this.locals
    const privateSettings = this.getStore('private-settings')
    const walletSettings = await privateSettings.get('wallet')
    const wallet = walletSettings?.wallets[walletName]
    if (wallet === undefined) {
      throw new WalletDesktopError('Wallet metadata not found')
    }
    const storeFeature = walletFactory.getWalletFeature<StoreFeatureOptions>(wallet.package, 'store')
    const builder: StoreBuilder = {
      id: this.getStoreId('wallet', walletName),
      options: async (migration) => {
        return await buildWalletStoreOptions(wallet, storeFeature?.opts, this.locals, migration.encKeys)
      }
    }
    await this.executeStoreBuilder(builder)
  }

  protected getStoreId <T extends StoreClass>(type: T, ...args: StoreClasses[T]): string {
    if (type === 'wallet') {
      return `wallet$$${args[0]}`
    } else {
      return `${type}$$`
    }
  }

  public getStoreById <T extends StoreClass>(storeId: string): Store<StoreModels[T]> {
    const store = this.stores[storeId]
    if (store === undefined) {
      throw new WalletDesktopError(`The store '${storeId}' is not initialized yet.`)
    }
    return store
  }

  public deconstructId <T extends StoreClass>(storeId: string): [type: T, ...args: StoreClasses[T]] {
    // type: T, ...args: StoreClasses[T]
    const regex = /([^$]+)\$\$(.+)?/
    const match = storeId.match(regex)
    if (match === null) {
      throw new WalletDesktopError(`Invalid store id '${storeId}'`)
    }

    const [, ...storeData] = match
    return storeData as any
  }

  public setStoreById <T extends StoreClass>(store: Store<StoreModels[T]>, storeId: string): void {
    if (this.stores[storeId] !== undefined) {
      throw new WalletDesktopError(`The store '${storeId}' is already initialized.`)
    }
    store.on('changed', () => this.onStoreChange(storeId, store))
    this.stores[storeId] = store
  }

  public setStore <T extends StoreClass>(store: Store<StoreModels[T]>, type: T, ...args: StoreClasses[T]): void {
    const storeId = this.getStoreId(type, ...args)
    this.setStoreById(store, storeId)
  }

  public hasStore <T extends StoreClass>(type: T, ...args: StoreClasses[T]): boolean {
    const storeId = this.getStoreId(type, ...args)
    return this.stores[storeId] !== undefined
  }

  public deleteStore <T extends StoreClass>(type: T, ...args: StoreClasses[T]): void {
    const storeId = this.getStoreId(type, ...args)
    const store = this.getStoreById(storeId)
    delete this.stores[storeId] // eslint-disable-line @typescript-eslint/no-dynamic-delete

    const path = store.getPath()
    if (existsSync(path)) {
      rmSync(path)
    }
  }

  public getStore <T extends StoreClass>(type: T, ...args: StoreClasses[T]): Store<StoreModels[T]> {
    const storeId = this.getStoreId(type, ...args)
    return this.getStoreById(storeId)
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

    // TODO: Check if the format is corret. If not fix corrupted data
    return await builder.build(this.ctx, this.locals, fixedOptions)
  }

  public async executeStoreBuilder (optionsBuilder: StoreBuilder): Promise<void> {
    const { needed } = this.ctx.storeMigrationProxy
    if (needed) {
      await this.migrateStore(optionsBuilder)
    } else {
      const options = await optionsBuilder.options({
        cwd: this.ctx.settingsPath,
        encKeys: this.locals.keysManager.encKeys
      })
      const store = await this.buildStore(options)
      this.setStoreById(store, optionsBuilder.id)
    }
  }

  private async migrateStore (optionsBuilder: StoreBuilder): Promise<void> {
    const { from, to } = this.ctx.storeMigrationProxy

    // Read old data
    const oldOptions = await optionsBuilder.options(from)
    const filepath = getPath(this.ctx, this.locals, oldOptions)
    const oldStore = await this.buildStore(oldOptions, from.storeType)
    const storeData = await oldStore.getStore()

    // Remove old store
    await fs.rm(filepath)

    // Create new store
    const newOptions = await optionsBuilder.options(to)
    const newStore = await this.buildStore(newOptions, to.storeType)
    await newStore.set(storeData)

    this.setStoreById(newStore, optionsBuilder.id)
  }

  protected async bundleStores (): Promise<StoresBundle> {
    const { versionManager } = this.locals
    const storesBundle: StoresBundle = {
      version: versionManager.softwareVersion,
      stores: {}
    }
    for (const [storeId, store] of Object.entries(this.stores)) {
      let metadata: StoreMetadata
      const [type, ...args] = this.deconstructId(storeId)
      if (type === 'wallet') {
        metadata = { type, walletName: args[0] }
      } else if (type === 'private-settings') {
        metadata = { type }
      } else {
        // Skip other stores
        continue
      }

      const storeBundle: StoreBundleData<any> = {
        metadata,
        data: await store.getStore()
      }
      storesBundle.stores[storeId] = storeBundle
    }
    return storesBundle
  }

  protected async uploadStores (): Promise<void> {
    const { sharedMemoryManager: sh, cloudVaultManager } = this.locals
    if (sh.memory.settings.cloud === undefined) {
      return
    }

    const bundle = await this.bundleStores()
    const bundleJSON = JSON.stringify(bundle)
    const buffer = Buffer.from(bundleJSON)

    const newTimestamp = await cloudVaultManager.updateStorage(buffer)

    // Update timestamp
    const publicSettings = this.getStore('public-settings')
    await publicSettings.set('cloud', {
      timestamp: newTimestamp,
      unsyncedChanges: false
    })
  }

  protected async restoreStoreBundle (bundle: StoresBundle): Promise<void> {
    const { versionManager } = this.locals
    if (bundle.version !== versionManager.softwareVersion) {
      // TODO: Handle version conflict!!
      return
    }

    for (const [, storeBundle] of Object.entries(bundle.stores)) {
      if (storeBundle.metadata.type === 'private-settings') {
        // Update shared memory with the

      }
    }
  }

  public async onStoreChangeAsync (storeId: string, store: Store<any>): Promise<void> {
    logger.debug(`The store has been changed ${store.getPath()}`)
    const [type] = this.deconstructId(storeId)
    if (type !== 'public-settings') {
      const publicSettings = this.getStore('public-settings')
      await publicSettings.set('cloud.unsyncedChanges', true)
      await this.uploadStores()
    }
  }

  public onStoreChange (storeId: string, store: Store<any>): void {
    this.onStoreChangeAsync(storeId, store).catch(...handleError(this.locals))
  }
}
