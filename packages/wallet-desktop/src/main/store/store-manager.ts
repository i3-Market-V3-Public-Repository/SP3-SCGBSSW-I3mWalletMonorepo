import { Store } from '@i3m/base-wallet'

import {
  createDefaultPrivateSettings,
  PrivateSettings,
  StoreSettings
} from '@wallet/lib'
import {
  handleErrorSync,
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
import { StoreClass, StoreClasses } from './store-class'
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

    await this.executeOptionsBuilders(async (migration) => ({
      defaults: Object.assign({}, createDefaultPrivateSettings(), publicSettingsValues),
      encryptionKey: await keysManager.computeSettingsKey(migration.encKeys),
      fileExtension: 'enc.json'
    }), 'private-settings')

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
          walletName: wallet.name,
          optionBuilder
        }
      })

    for (const { walletName, optionBuilder } of walletOptionsBuilders) {
      await this.executeOptionsBuilders(optionBuilder, 'wallet', walletName)
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
    const builder: StoreOptionsBuilder<StoreModel> = async (migration) => {
      return await this.builder.buildWalletStoreOptions(wallet, storeFeature?.opts, migration.encKeys)
    }

    await this.executeOptionsBuilders(builder, 'wallet', walletName)
  }

  //
  // (): Store<StoreModels[T]> {
  protected async executeOptionsBuilders <T extends StoreClass>(
    optionsBuilder: StoreOptionsBuilder<any>,
    type: T,
    ...args: StoreClasses[T]
  ): Promise<void> {
    const store = await this.builder.buildOptionsBuilder(optionsBuilder)

    const storeProxy = new StoreProxy(store)
    const beforeChange = async (): Promise<void> => {
      await this.onBeforeChange(type, store)
    }
    const afterChange = async (): Promise<void> => {
      await this.onAfterChange(type, store)
    }
    const afterDelete = async (): Promise<void> => {
      storeProxy.off('before-set', beforeChange)
      storeProxy.off('after-set', afterChange)
      storeProxy.off('after-delete', afterDelete)
    }

    storeProxy.on('before-set', beforeChange)
    storeProxy.on('after-set', afterChange)
    storeProxy.on('after-delete', afterDelete)

    const id = StoreBag.getStoreId(type, ...args)
    this.setStoreById(storeProxy.proxy, id)
    this.silentBag.setStoreById(store, id)
  }

  // Cloud Sync

  protected async bundleStores (): Promise<StoresBundle> {
    const { versionManager } = this.locals
    const storesBundle: StoresBundle = {
      version: versionManager.softwareVersion,
      stores: {}
    }
    for (const [storeId, store] of Object.entries(this.stores)) {
      const idMetadata = StoreBag.deconstructId(storeId)
      const type = idMetadata[0]

      if (type === 'public-settings') {
        continue
      }

      const metadata: StoreMetadata = {
        idMetadata
      }

      const storeBundle: StoreBundleData = {
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
    const { versionManager, sharedMemoryManager: sh } = this.locals
    if (bundle.version !== versionManager.softwareVersion) {
      // TODO: Handle version conflict!!
      return
    }

    for (const [, storeBundle] of Object.entries(bundle.stores)) {
      const { idMetadata } = storeBundle.metadata
      const type = idMetadata[0]
      if (!this.hasStore(...idMetadata)) {
        // Create the store first
      }

      const store = this.silentBag.getStore(...idMetadata)
      await store.set(storeBundle.data)

      if (type === 'private-settings') {
        sh.update(mem => ({
          ...mem,
          settings: storeBundle.data as PrivateSettings
        }))
      }
    }
  }

  //
  protected async onBeforeChange (type: StoreClass, store: Store<any>): Promise<void> {
    console.log('Store changed!', store.getPath())

    if (isEncryptedStore(type)) {
      const publicSettings = this.getStore('public-settings')
      await publicSettings.set('cloud.unsyncedChanges', true)
    }
  }

  protected async onAfterChange (type: StoreClass, store: Store<any>): Promise<void> {
    logger.debug(`The store has been changed ${store.getPath()}`)
    if (isEncryptedStore(type)) {
      await this.uploadStores().catch((err: Error) => {
        let fixedError = err
        if (!(err instanceof WalletDesktopError)) {
          fixedError = new WalletDesktopError('Could not uplaod stores', {
            severity: 'error',
            message: 'Upload store error',
            details: `Could not upload store due to '${err.message}'`
          })
        }
        handleErrorSync(this.locals, fixedError)
      })
    }
  }
}

type EncryptedStoreClass = 'wallet' | 'private-settings'
function isEncryptedStore (type: StoreClass): type is EncryptedStoreClass {
  return type !== 'public-settings'
}
