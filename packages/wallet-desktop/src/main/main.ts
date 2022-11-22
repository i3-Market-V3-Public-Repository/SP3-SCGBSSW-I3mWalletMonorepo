import { app, BrowserWindow, session, dialog } from 'electron'
import path from 'path'
import { generateSecret, exportJWK, importJWK, JWK } from 'jose'
import packageJson from '../../package.json'

import { initContext, Provider } from '@wallet/lib'

import {
  logger,
  Locals,
  WindowManager,
  Tray,
  ApiManager,
  MainContext,
  FeatureManager,
  initSettings,
  SharedMemoryManager,
  WalletFactory,
  ElectronDialog,
  ToastManager,
  StartFeatureError,
  ActionReducer,
  LocalAuthentication,
  ConnectManager,
  VersionManager
} from './internal'

function validProviders (providers: Provider[]): boolean {
  if (providers === undefined || providers.length === 0) {
    return false
  }

  // Creates an object which parameters say if all providers have this field set
  const filledArguments = providers.reduce((prev, curr) => ({
    name: prev.name || curr.name === undefined,
    provider: prev.provider || curr.provider === undefined,
    network: prev.network || curr.network === undefined,
    rpcUrl: prev.rpcUrl || curr.rpcUrl === undefined
  }), { name: false, provider: false, network: false, rpcUrl: false })

  return Object.values(filledArguments).reduce((prev, curr) => prev && !curr, true)
}

async function getAppSettings (locals: Locals): Promise<MainContext> {
  const sharedMemoryManager = new SharedMemoryManager()
  locals.sharedMemoryManager = sharedMemoryManager

  const settings = initSettings({
    cwd: app.getPath('userData')
  }, sharedMemoryManager)
  const providers = settings.get('providers')

  // Setup default providers
  if (!validProviders(providers)) {
    settings.set('providers', [
      { name: 'Rinkeby', provider: 'did:ethr:rinkeby', network: 'rinkeby', rpcUrl: 'https://rpc.ankr.com/eth_rinkeby' },
      { name: 'i3Market', provider: 'did:ethr:i3m', network: 'i3m', rpcUrl: 'http://95.211.3.250:8545' }
    ])
  }

  const wallet = settings.get('wallet')
  wallet.packages = [
    '@i3m/sw-wallet',
    '@i3m/bok-wallet'
  ]
  settings.set('wallet', wallet)

  const secret = settings.get('secret')
  if (secret === undefined) {
    const key = await generateSecret('HS256', { extractable: true })
    const jwk = await exportJWK(key)
    settings.set('secret', jwk)
  }

  // Syncronize shared memory and settings
  sharedMemoryManager.update((mem) => ({
    ...mem,
    settings: settings.store
  }))
  sharedMemoryManager.on('change', (mem) => {
    settings.set(mem.settings)
  })

  locals.settings = settings

  const ctx = initContext<MainContext>({
    appPath: path.resolve(__dirname, '../../')
  })

  return ctx
}

async function initActions (ctx: MainContext, locals: Locals): Promise<void> {
  locals.actionReducer = new ActionReducer(locals)
}

async function initUI (ctx: MainContext, locals: Locals): Promise<void> {
  locals.windowManager = new WindowManager(locals)
  if (process.env.REACT_DEVTOOLS !== undefined) {
    await session.defaultSession.loadExtension(process.env.REACT_DEVTOOLS)
  }

  locals.tray = new Tray(locals)
  locals.dialog = new ElectronDialog(locals)
  locals.toast = new ToastManager(locals)

  // // Quit when all windows are closed, except on macOS. There, it's common
  // // for applications and their menu bar to stay active until the user quits
  // // explicitly with Cmd + Q.
  app.on('window-all-closed', () => {
    // if (process.platform !== 'darwin') {
    //   app.quit()
    // }
    // Do not close the application even if all windows are closed
    logger.debug('All windows are closed')
  })

  //
  app.on('activate', function () {
    // On macOS it's common to re-create a window in the app when the
    // dock icon is clicked and there are no other windows open.
    if (BrowserWindow.getAllWindows().length === 0) {
      locals.windowManager.openMainWindow()
    }
  })
}

async function initVersionManager (ctx: MainContext, locals: Locals): Promise<void> {
  const versionManager = new VersionManager(locals)
  await versionManager.initialize()
  locals.versionManager = versionManager

  if (await versionManager.needsUpdate()) {
    locals.toast.show({
      message: 'Update pending...',
      details: `Your current version (${versionManager.currentVersion}) is outdated. \n Please, download the latest release (${versionManager.latestVersion}) going to 'Help → Latest Release'.`,

      type: 'warning',
      timeout: 0 // never close this alert!
    })
  }
}

async function initAuth (ctx: MainContext, locals: Locals): Promise<void> {
  const auth = new LocalAuthentication(locals)
  locals.auth = auth

  await auth.authenticate()
}

async function initFeatureManager (ctx: MainContext, locals: Locals): Promise<void> {
  locals.featureManager = new FeatureManager()
  locals.featureContext = {}
}

async function initApi (
  ctx: MainContext,
  locals: Locals
): Promise<void> {
  // Create and initialize connect manager
  // FIXME: Important bug!? The secret is accesible on the disk...
  // Maybe derivate the secret from the password?
  const jwk = locals.settings.get('secret') as JWK
  const key = await importJWK(jwk, 'HS256')
  locals.connectManager = new ConnectManager(locals, key)
  await locals.connectManager.initialize()

  // Create and initialize api manager
  locals.apiManager = new ApiManager(locals)
  await locals.apiManager.initialize()
}

async function initWalletFactory (
  ctx: MainContext,
  locals: Locals
): Promise<void> {
  locals.walletFactory = new WalletFactory(locals)
  await locals.walletFactory.initialize()
}

/**
 * Desktop Wallet startup function
 */
async function onReady (): Promise<void> {
  const locals: Locals = { packageJson } as any
  const ctx = await getAppSettings(locals)

  await initActions(ctx, locals)
  await initUI(ctx, locals)
  await initVersionManager(ctx, locals)
  await initFeatureManager(ctx, locals)
  await initApi(ctx, locals)

  await initAuth(ctx, locals)
  await initWalletFactory(ctx, locals)

  // Launch UI
  const { windowManager } = locals
  windowManager.openMainWindow('/wallet')
}

export default async (argv: string[]): Promise<void> => {
  // This method will be called when Electron has finished
  // initialization and is ready to create browser windows.
  // Some APIs can only be used after this event occurs.
  app.on('ready', () => {
    const singleInstance = app.requestSingleInstanceLock()
    if (!singleInstance) {
      logger.warn('The application is already running')
      dialog.showErrorBox('Cannot start', 'The application is already running. Check your tray.')
      app.quit()
      return
    }

    onReady().catch((err) => {
      if (err instanceof StartFeatureError && err.exit) {
        return app.quit()
      }

      if (err instanceof Error) {
        logger.error(err.stack)
      } else {
        logger.error(err)
      }
    })
  })
}
