import { app, BrowserWindow, session } from 'electron'
import path from 'path'

import { initContext } from '@wallet/lib'

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
  StartFeatureError,
  ActionReducer
} from './internal'

async function getAppSettings (locals: Locals): Promise<MainContext> {
  const sharedMemoryManager = new SharedMemoryManager()
  locals.sharedMemoryManager = sharedMemoryManager

  const settings = initSettings({
    cwd: app.getPath('userData')
  }, sharedMemoryManager)
  const providers = settings.get('providers')

  // Setup default providers
  if (providers === undefined || providers.length === 0) {
    settings.set('providers', [
      { name: 'Rinkeby', provider: 'did:ethr:rinkeby' },
      { name: 'i3Market', provider: 'did:ethr:i3m' }
    ])
  }

  const wallet = settings.get('wallet')
  wallet.packages = [
    '@i3-market/sw-wallet',
    '@i3-market/bok-wallet'
  ]
  settings.set('wallet', wallet)

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
    appPath: path.resolve(__dirname, '../')
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

async function initFeatureManager (ctx: MainContext, locals: Locals): Promise<void> {
  locals.featureManager = new FeatureManager()
  locals.featureContext = {}
}

async function initApi (
  ctx: MainContext,
  locals: Locals
): Promise<void> {
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
  const locals: Locals = {} as any
  const ctx = await getAppSettings(locals)

  await initActions(ctx, locals)
  await initUI(ctx, locals)
  await initFeatureManager(ctx, locals)
  await initApi(ctx, locals)

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
