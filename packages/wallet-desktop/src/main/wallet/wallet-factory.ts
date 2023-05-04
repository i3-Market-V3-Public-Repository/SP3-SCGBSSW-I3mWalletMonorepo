import { DEFAULT_PROVIDERS_DATA, ProviderData, Wallet, WalletBuilder, WalletMetadata } from '@i3m/base-wallet'
import { TaskDescription, WalletInfo, WalletMetadataMap } from '@wallet/lib'
import {
  Feature, FeatureHandler, FeatureManager, FeatureType, handleErrorCatch, LabeledTaskHandler, Locals, logger, MainContext, StartFeatureError, storeFeature, WalletDesktopError
} from '@wallet/main/internal'

import { InvalidWalletError, NoWalletSelectedError } from './errors'
import { WalletFactoryFlows } from './wallet-factory-flows'

interface WalletFeatureMap {
  [name: string]: Array<Feature<any>> | undefined
}

interface FeatureMap {
  [name: string]: FeatureHandler<any>
}

const featureMap: FeatureMap = {
  store: storeFeature
}

export class WalletFactory {
  protected _wallet: Wallet | undefined
  protected _walletName: string | undefined

  protected flows: WalletFactoryFlows
  protected featuresByWallet: WalletFeatureMap

  static async initialize (ctx: MainContext, locals: Locals): Promise<WalletFactory> {
    return new WalletFactory(locals)
  }

  constructor (protected locals: Locals) {
    this.featuresByWallet = {}
    this.flows = new WalletFactoryFlows(locals)
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

      const forceWalletPromise = this.forceOneWallet()
      forceWalletPromise.catch(...handleErrorCatch(this.locals))
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

    const walletInfo = wallet.wallets[currentWallet]
    if (walletInfo === undefined) {
      throw new WalletDesktopError('cannot load current wallet: inconsistent data', {
        message: 'Load Wallet',
        details: 'Cannot load current wallet: inconsistent data',
        severity: 'error'
      })
    }

    await this.changeWallet(walletInfo)
  }


  protected setWallet (walletInfo: WalletInfo, wallet: Wallet) {
    this._walletName = walletInfo.name
    this._wallet = wallet
  }

  protected unsetWallet () {
    this._walletName = undefined
    this._wallet = undefined
  }

  // **** External utilities ****
  async createWallet (): Promise<WalletInfo> {
    const { sharedMemoryManager: shm, featureManager } = this.locals
    const walletInfo = await this.flows.getNewWalletInfo()

    try {
      await this.changeWallet(walletInfo)
    } catch (err) {
      // Create a floating feature manager
      if (featureManager.hasFeatures) {
        await featureManager.delete()
        await featureManager.clearFeatures()
      }

      throw new WalletDesktopError('wallet was not created because the initialization was cancelled or failed.', {
        message: 'Create wallet',
        details: 'Wallet was not created because the initialization was cancelled or failed.',
        severity: 'warning'
      })
    }

    // Write the new wallet info
    const name = walletInfo.name
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
    return await this.flows.selectWallet(walletName)
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
    await featureManager.loadWalletFeatures(walletInfo)
    await featureManager.delete()

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

  // ***** Internal features *****
  protected async buildWalletTask (walletInfo: WalletInfo, task: LabeledTaskHandler): Promise<Wallet> {
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
      if (featureManager.hasFeatures) {
        await featureManager.clearFeatures()
      }

      await featureManager.loadWalletFeatures(walletInfo)
      await featureManager.start()

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

  protected async buildWallet (walletInfo: WalletInfo): Promise<Wallet> {
    const taskInfo: TaskDescription = {
      title: 'Build Wallet',
      details: `Building wallet ${walletInfo.name}`
    }
    return await this.locals.taskManager.createTask('labeled', taskInfo, async (task) => {
      return await this.buildWalletTask(walletInfo, task)
    })
  }

  async forceOneWallet (): Promise<void> {
    //
    while (!this.hasWalletsCreated) {
      await this.createWallet().catch(...handleErrorCatch(this.locals))
    }
  }

  async changeWallet (walletInfo: WalletInfo): Promise<void> {
    const walletName = walletInfo.name
    if (walletName === this._walletName) {
      return
    }

    logger.info(`Change wallet to ${walletName}`)
    const { apiManager } = this.locals

    // Stop API
    await apiManager.close()

    // Build the current wallet
    try {
      const wallet = await this.buildWallet(walletInfo)
      this.setWallet(walletInfo, wallet)
    } catch (err) {
      this.unsetWallet()
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
      throw new WalletDesktopError(`could not change to wallet '${walletName}'`, {
        message: 'Wallet initialization',
        details: `Could not initialize the wallet '${walletName}'`,
        severity: 'warning'
      })
    }

    this.locals.toast.show({
      message: 'Wallet select',
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

  getWalletFeatureByType <T>(walletPackage: string, featureName: FeatureType): Feature<T> | undefined {
    const features = this.getWalletFeatures<T>(walletPackage)
    const feature = features.reduce<Feature<T> | undefined>((prev, curr) => {
      if (curr.handler.name === featureName) {
        return curr
      }
      return prev
    }, undefined)
    return feature
  }

  get walletPackages (): string[] {
    return this.locals.sharedMemoryManager.memory.settings.private.wallet.packages
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
