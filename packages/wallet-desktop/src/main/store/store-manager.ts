import { Store } from '@i3m/base-wallet'

import {
  createDefaultPrivateSettings,
  StoreSettings
} from '@wallet/lib'
import {
  handleError,
  Locals,
  logger,
  MainContext,
  PublicSettingsOptions,
  softwareVersion,
  StoreFeatureOptions,
  StoreModel,
  WalletDesktopError
} from '@wallet/main/internal'
import { currentStoreType } from './builders'
import { StoreOptionsBuilder } from './migration'
import { StoreBag } from './store-bag'
import { StoreBuilder } from './store-builder'
import { StoreBundleData, StoreMetadata, StoresBundle } from './store-bundle'
import { StoreClasses, StoreModels } from './store-class'
import { StoreProxy } from './store-proxy'

const DEFAULT_STORE_SETTINGS: StoreSettings = { type: 'electron-store' }
export class StoreManager extends StoreBag {
  builder: StoreBuilder
  silentBag: StoreBag

  constructor (protected ctx: MainContext, protected locals: Locals) {
    super()
    this.builder = new StoreBuilder(ctx, locals)
    this.silentBag = new StoreBag()
  }

  // Class utils

  public async loadPublicStores (): Promise<void> {
    const options: PublicSettingsOptions = {
      defaults: { version: softwareVersion(this.locals) }
    }

    // NOTE: Public settings must always be not encrypted and using the electorn store.
    // This guarantees compatibilities with future versions!
    const publicSettings = await this.builder.buildStore(options, 'electron-store')
    this.setStore(publicSettings, 'public-settings')

    // Migrate to last store type
    this.builder.storeInfo = await publicSettings.get('store') ?? DEFAULT_STORE_SETTINGS
    if (this.builder.storeInfo.type !== currentStoreType) {
      this.ctx.storeMigrationProxy.from.storeType = this.builder.storeInfo.type
      this.ctx.storeMigrationProxy.to.storeType = currentStoreType
      this.ctx.storeMigrationProxy.migrations.push(async (to) => {
        this.builder.storeInfo.type = to.storeType
        await publicSettings.set('store', { type: to.storeType })
      })
    }
  }

  public async loadEncryptedStores (): Promise<void> {
    const { keysManager, walletFactory } = this.locals
    const publicSettings = this.getStore('public-settings')
    const publicSettingsValues = await publicSettings.getStore()

    const id = StoreBag.getStoreId('private-settings')
    await this.executeOptionsBuilders(id, async (migration) => ({
      defaults: Object.assign({}, createDefaultPrivateSettings(), publicSettingsValues),
      encryptionKey: await keysManager.computeSettingsKey(migration.encKeys),
      fileExtension: 'enc.json'
    }))

    const privateSettings = this.getStore('private-settings')
    const walletSettings = await privateSettings.get('wallet')
    const walletOptionsBuilders = Object
      .values(walletSettings.wallets)
      .map((wallet) => ({
        wallet,
        storeFeature: walletFactory.getWalletFeature<StoreFeatureOptions>(wallet.package, 'store')
      }))
      .filter(({ storeFeature }) => storeFeature !== undefined)
      .map(({ wallet, storeFeature }) => {
        const optionBuilder: StoreOptionsBuilder<any> = async (migration) => await this.builder.buildWalletStoreOptions(wallet, storeFeature?.opts, migration.encKeys)

        return {
          id: StoreBag.getStoreId('wallet', wallet.name),
          optionBuilder
        }
      })

    for (const { id, optionBuilder } of walletOptionsBuilders) {
      await this.executeOptionsBuilders(id, optionBuilder)
    }

    const ps = this.silentBag.getStore('private-settings')
    await ps.set<'developer'>('developer', {
      enableDeveloperApi: true,
      enableDeveloperFunctions: true
    })
  }

  public async migrate (): Promise<void> {
    const { to, migrations } = this.ctx.storeMigrationProxy

    for (const migration of migrations) {
      await migration(to)
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
    const id = StoreBag.getStoreId('wallet', walletName)
    const builder: StoreOptionsBuilder<StoreModel> = async (migration) => {
      return await this.builder.buildWalletStoreOptions(wallet, storeFeature?.opts, migration.encKeys)
    }

    await this.executeOptionsBuilders(id, builder)
  }

  //

  protected async executeOptionsBuilders (id: string, optionsBuilder: StoreOptionsBuilder<any>): Promise<void> {
    for (const bag of [this, this.silentBag]) {
      const store = await this.builder.buildOptionsBuilder(optionsBuilder, bag === this)
      bag.setStoreById(store, id)
    }
  }

  // Cloud Sync

  public setStoreById<T extends keyof StoreClasses>(store: Store<StoreModels[T]>, storeId: string): void {
    const storeProxy = new StoreProxy(store)
    storeProxy.on('before-set', async () => {
      console.log('Before set!!')
    })

    super.setStoreById(storeProxy.proxy, storeId)
    store.on('changed', () => this.onStoreChange(storeId, store))
  }

  protected async bundleStores (): Promise<StoresBundle> {
    const { versionManager } = this.locals
    const storesBundle: StoresBundle = {
      version: versionManager.softwareVersion,
      stores: {}
    }
    for (const [storeId, store] of Object.entries(this.stores)) {
      let metadata: StoreMetadata
      const [type, ...args] = StoreBag.deconstructId(storeId)
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

  public async restoreStoreBundle (bundle: StoresBundle): Promise<void> {
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

  //

  protected onStoreChange (storeId: string, store: Store<any>): void {
    const onStoreChangeAsync = async (): Promise<void> => {
      logger.debug(`The store has been changed ${store.getPath()}`)
      const [type] = StoreBag.deconstructId(storeId)
      if (type !== 'public-settings') {
        const publicSettings = this.getStore('public-settings')
        await publicSettings.set('cloud.unsyncedChanges', true)
        await this.uploadStores()
      }
    }

    onStoreChangeAsync().catch(...handleError(this.locals))
  }
}
