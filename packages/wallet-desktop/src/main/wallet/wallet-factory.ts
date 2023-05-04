import { DEFAULT_PROVIDERS_DATA, Descriptors, ProviderData, Wallet, WalletBuilder, WalletMetadata } from '@i3m/base-wallet'
import { Provider, TaskDescription, WalletInfo, WalletMetadataMap } from '@wallet/lib'
import {
  Feature, FeatureHandler, FeatureManager, FeatureType, LabeledTaskHandler, Locals, logger, MainContext, StartFeatureError, storeFeature, WalletDesktopError
} from '@wallet/main/internal'
import { v4 as uuid } from 'uuid'

import { InvalidWalletError, NoWalletSelectedError } from './errors'

interface WalletFeatureMap {
  [name: string]: Array<Feature<any>> | undefined
}

interface FeatureMap {
  [name: string]: FeatureHandler<any>
}

interface WalletCreationForm {
  name: string
  walletMetadata: [string, WalletMetadata]
  provider: Provider
}

const featureMap: FeatureMap = {
  store: storeFeature
}

export class WalletFactory {
  protected _wallet: Wallet | undefined
  protected _walletName: string | undefined

  protected featuresByWallet: WalletFeatureMap

  static async initialize (ctx: MainContext, locals: Locals): Promise<WalletFactory> {
    return new WalletFactory(locals)
  }

  constructor (protected locals: Locals) {
    this._walletName = undefined
    this.featuresByWallet = {}
    this.bindRuntimeEvents()
  }

  protected bindRuntimeEvents (): void {
    const { runtimeManager } = this.locals
    runtimeManager.on('wallet-metadatas', async () => {
      await this.loadDefaultProviders()
      await this.loadWalletsMetadata()
    })

    runtimeManager.on('ui', async () => {
      await this.loadCurrentWallet()

      //
      if (!this.hasWalletsCreated) {
        await this.createWallet()
      }
    })
  }

  async loadDefaultProviders (): Promise<void> {
    const { sharedMemoryManager: shm } = this.locals
    shm.update((mem) => ({
      ...mem,
      defaultProviders: DEFAULT_PROVIDERS_DATA
    }))
  }

  async loadWalletsMetadata (): Promise<void> {
    const walletsMetadata: WalletMetadataMap = {}
    for (const walletPackage of this.walletPackages) {
      const packageJson = await import(`${walletPackage}/package.json`)
      logger.info(`Loaded metadata for wallet '${walletPackage}'`)

      // Store wallet metadata
      const walletMetadata: WalletMetadata = packageJson.walletMetadata
      walletsMetadata[walletPackage] = walletMetadata

      // Initialize features
      const features: Array<Feature<any>> = []
      for (const [name, featureArgs] of Object.entries(walletMetadata.features)) {
        features.push(FeatureManager.CreateFeature(featureMap[name], featureArgs))
      }
      this.featuresByWallet[walletPackage] = features
    }

    const { sharedMemoryManager } = this.locals
    sharedMemoryManager.update((mem) => ({
      ...mem,
      walletsMetadata
    }))
  }

  async loadCurrentWallet (): Promise<void> {
    const { sharedMemoryManager: shm } = this.locals
    const { wallet } = shm.memory.settings.private
    const currentWallet = shm.memory.settings.public.currentWallet
    if (currentWallet === undefined) {
      logger.debug('No wallets stored into the configuration')
      return
    }
    logger.debug(`The current configuration has the following wallets: ${Object.keys(wallet.wallets).join(', ')}`)

    await this.changeWallet(currentWallet)
  }

  async buildWalletTask (walletInfo: WalletInfo, task: LabeledTaskHandler): Promise<Wallet> {
    const { sharedMemoryManager: shm, featureContext, featureManager, dialog, toast } = this.locals
    const { providers } = shm.memory.settings.private
    const providersData = providers.reduce<Record<string, ProviderData>>(
      (prev, curr) => {
        prev[`did:ethr:${curr.network}`] = curr
        return prev
      }, { ...DEFAULT_PROVIDERS_DATA })

    try {
      // Init wallet features
      // Initialize all the features
      await featureManager.clearFeatures(walletInfo.name)
      const features = this.featuresByWallet[walletInfo.package]
      if (features !== undefined) {
        for (const feature of features) {
          featureManager.addFeature(feature)
        }
      }
      await featureManager.start(walletInfo.name)

      // Initialize wallet
      const walletMain: WalletBuilder<any> = (await import(walletInfo.package)).default
      const wallet = await walletMain({
        ...walletInfo.args,

        store: featureContext.store,
        toast,
        dialog,
        providersData
      })

      return wallet
    } catch (err) {
      // Start errors should be bypassed
      if (err instanceof StartFeatureError) {
        throw err
      }
      if (err instanceof Error) {
        logger.error(err.stack)
      } else {
        logger.error(err)
      }

      throw new InvalidWalletError(`Cannot initialize the wallet '${walletInfo.name}'`)
    }
  }

  providerSelect (providers: Provider[]): Descriptors<Provider> {
    const completeProviderList: Provider[] = [
      ...Object.values(DEFAULT_PROVIDERS_DATA).map((provider) => ({
        ...provider,
        name: provider.network
      })),
      ...providers
    ]
    return {
      type: 'select',
      message: 'Select a network',
      values: completeProviderList,
      getText (provider) {
        return provider.name
      }
    }
  }

  async createWallet (): Promise<WalletInfo> {
    const { sharedMemoryManager: shm, dialog } = this.locals
    const walletPackages = shm.memory.walletsMetadata
    const privateSettings = shm.memory.settings.private

    const walletCreationForm = await dialog.form<WalletCreationForm>({
      title: 'Wallet creation',
      descriptors: {
        name: { type: 'text', message: 'Introduce a name for the wallet', allowCancel: false },
        walletMetadata: {
          type: 'select',
          message: 'Select a wallet type',
          values: Object.entries<WalletMetadata>(walletPackages),
          getText ([walletPackage, walletMetadata]) {
            return walletMetadata.name
          }
        },
        provider: this.providerSelect(privateSettings.providers)
      },
      order: ['name', 'walletMetadata', 'provider']
    })

    if (walletCreationForm === undefined) {
      throw new WalletDesktopError('cannot create wallet: dialog cancelled', {
        message: 'Create Wallet',
        severity: 'warning',
        details: 'Dialog cancelled'
      })
    }

    // Wallet already exists
    if (walletCreationForm.name in privateSettings.wallet.wallets) {
      throw new WalletDesktopError(`cannot create wallet: ${walletCreationForm.name} already exists`, {
        message: 'Create Wallet',
        severity: 'warning',
        details: `Wallet ${walletCreationForm.name} already exists`
      })
    }

    const walletInfo: WalletInfo = {
      name: walletCreationForm.name,
      package: walletCreationForm.walletMetadata[0],
      store: uuid(),
      args: {
        provider: `did:ethr:${walletCreationForm.provider.network}`
      }
    }

    try {
      await this.buildWallet(walletInfo)
    } catch (err) {
      // Create a floating feature manager
      const featureManager = new FeatureManager(this.locals)
      const features = this.featuresByWallet[walletInfo.package]
      if (features !== undefined) {
        for (const feature of features) {
          featureManager.addFeature(feature)
        }
      }
      await featureManager.delete(walletInfo.name)

      throw new WalletDesktopError('wallet was not created because the initialization was cancelled or failed.', {
        message: 'Create wallet',
        details: 'Wallet was not created because the initialization was cancelled or failed.',
        severity: 'warning'
      })
    }

    // Write the new wallet info
    const name = walletCreationForm.name
    shm.update((mem) => ({
      ...mem,
      settings: {
        ...mem.settings,
        private: {
          ...mem.settings.private,
          wallet: {
            ...mem.settings.private.wallet,
            // Add the wallet to the wallet map
            wallets: {
              ...mem.settings.private.wallet.wallets,
              [name]: walletInfo
            }
          }
        },
        public: {
          ...mem.settings.public,
          currentWallet: name
        }
      }
    }))

    return walletInfo
  }

  async selectWallet (walletName?: string): Promise<string> {
    const { sharedMemoryManager: shm, dialog } = this.locals
    if (walletName === undefined) {
      walletName = await dialog.select({
        values: this.walletNames
      })
    }

    if (walletName === undefined) {
      throw new WalletDesktopError('cannot change wallet: user cancelled', {
        message: 'Select wallet',
        severity: 'warning',
        details: 'User cancelled'
      })
    }

    if (walletName === shm.memory.settings.public.currentWallet) {
      return walletName
    }

    shm.update((mem) => ({
      ...mem,
      settings: {
        ...mem.settings,
        private: {
          ...mem.settings.private,
          wallet: {
            ...mem.settings.private.wallet
          }
        },
        public: {
          ...mem.settings.public,
          currentWallet: walletName
        }
      },
      identities: {},
      resources: {}
    }))

    return walletName
  }

  async buildWallet (walletInfo: WalletInfo): Promise<Wallet> {
    const taskInfo: TaskDescription = {
      title: 'Build Wallet',
      details: `Building wallet ${walletInfo.name}`
    }
    return await this.locals.taskManager.createTask('labeled', taskInfo, async (task) => {
      return await this.buildWalletTask(walletInfo, task)
    })
  }

  async deleteWallet (walletName: string): Promise<void> {
    const { sharedMemoryManager: shm } = this.locals
    const { wallets } = shm.memory.settings.private.wallet
    const currentWallet = shm.memory.settings.public.currentWallet

    const { [walletName]: walletInfo, ...newWallets } = wallets
    if (walletInfo === undefined) {
      throw new Error('Inconsistent data!')
    }

    // Create a floating feature manager
    const featureManager = new FeatureManager(this.locals)
    const features = this.featuresByWallet[walletInfo.package]
    if (features !== undefined) {
      for (const feature of features) {
        featureManager.addFeature(feature)
      }
    }
    await featureManager.delete(walletName)

    this.locals.sharedMemoryManager.update((mem) => {
      let current = currentWallet
      let resources = mem.resources
      let identities = mem.identities
      if (current === walletName) {
        current = undefined
        resources = {}
        identities = {}
      }

      return {
        ...mem,
        settings: {
          ...mem.settings,
          private: {
            ...mem.settings.private,
            wallet: {
              ...mem.settings.private.wallet,
              wallets: newWallets
            }
          },
          public: {
            ...mem.settings.public,
            currentWallet: current
          }
        },
        resources,
        identities
      }
    })
  }

  async changeWallet (walletName: string): Promise<void> {
    if (walletName === this._walletName) {
      return
    }

    logger.info(`Change wallet to ${walletName}`)
    const { apiManager, sharedMemoryManager: shm } = this.locals

    // Stop API
    await apiManager.close()

    // Build the current wallet
    try {
      const walletInfo = shm.memory.settings.private.wallet.wallets[walletName]
      if (walletInfo === undefined) {
        throw new Error('Inconsistent data!')
      }

      this._wallet = await this.buildWallet(walletInfo)
      this._walletName = walletName
    } catch (err) {
      this._wallet = undefined
      this._walletName = undefined
      console.trace(err)
      this.locals.toast.show({
        message: 'Wallet initialization',
        details: `Could not initialize the wallet '${walletName}'`,
        type: 'warning'
      })
      this.locals.sharedMemoryManager.update((mem) => ({
        ...mem,
        settings: {
          ...mem.settings,
          private: {
            ...mem.settings.private,
            wallet: {
              ...mem.settings.private.wallet
            }
          },
          public: {
            ...mem.settings.public,
            currentWallet: undefined
          }
        }
      }))
      return
    }

    this.locals.toast.show({
      message: 'Wallet change',
      type: 'info',
      details: `Using wallet '${walletName}'`
    })

    await this.refreshWalletData()

    // Start API
    await apiManager.listen()
  }

  async refreshWalletData (): Promise<void> {
    const { sharedMemoryManager: shm } = this.locals

    // Setup the resource list inside shared memory
    const identities = await this.wallet.getIdentities()
    const resources = await this.wallet.getResources()
    shm.update((mem) => ({
      ...mem, identities, resources
    }))
  }

  getWalletFeatures <T>(walletPackage: string): Array<Feature<T>> {
    const features = this.featuresByWallet[walletPackage]
    if (features === undefined) {
      throw new WalletDesktopError('Wallet features not defined')
    }
    return features
  }

  getWalletFeature <T>(walletPackage: string, featureName: FeatureType): Feature<T> | undefined {
    const features = this.getWalletFeatures<T>(walletPackage)
    const feature = features.reduce<Feature<T> | undefined>((prev, curr) => {
      if (curr.handler.name === featureName) {
        return curr
      }
      return prev
    }, undefined)
    return feature
  }

  get walletNames (): string[] {
    return Object.keys(this.locals.sharedMemoryManager.memory.settings.private.wallet.wallets)
  }

  get walletPackages (): string[] {
    return this.locals.sharedMemoryManager.memory.settings.private.wallet.packages
  }

  get walletName (): string | undefined {
    return this._walletName
  }

  get wallet (): Wallet {
    if (this._wallet === undefined) {
      throw new NoWalletSelectedError('Wallet not select. Maybe you might initialize the wallet factory first.')
    }

    return this._wallet
  }

  get hasWalletSelected (): boolean {
    return this._wallet !== undefined
  }

  get hasWalletsCreated (): boolean {
    return Object.keys(this.locals.sharedMemoryManager.memory.settings.private.wallet.wallets).length > 0
  }
}
