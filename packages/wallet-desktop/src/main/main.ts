import { app, BrowserWindow, session, dialog } from 'electron'
import path from 'path'
import { importJWK, JWK } from 'jose'
import packageJson from '../../package.json'

import { initContext } from '@wallet/lib'

import {
  logger,
  Locals,
  WindowManager,
  Tray,
  ApiManager,
  MainContext,
  FeatureManager,
  SharedMemoryManager,
  WalletFactory,
  ElectronDialog,
  ToastManager,
  ActionReducer,
  KeysManager,
  ConnectManager,
  VersionManager,
  initPrivateSettings,
  initPublicSettings,
  StoreManager,
  handleError
} from './internal'
import { createStoreMigrationProxy } from './store/migration'

async function initApplication (ctx: MainContext, locals: Locals): Promise<void> {
  const sharedMemoryManager = new SharedMemoryManager()
  locals.sharedMemoryManager = sharedMemoryManager

  const storeManager = new StoreManager(ctx, locals)
  await storeManager.initialize()
  locals.storeManager = storeManager

  const publicSettings = await initPublicSettings({ cwd: ctx.settingsPath }, locals)
  locals.publicSettings = publicSettings
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
  locals.versionManager = versionManager

  await versionManager.initialize()
  await versionManager.verifySettingsVersion()

  // Do not await verifyLatestVersion!
  // If there is no internet connection it will freeze the application
  versionManager.verifyLatestVersion().catch(...handleError(locals))
}

async function initAuth (ctx: MainContext, locals: Locals): Promise<void> {
  const keysManager = new KeysManager(ctx, locals)
  locals.keysManager = keysManager

  await keysManager.initialize()
  await keysManager.authenticate()

  // Migrate stores (if needed)
  await locals.storeManager.migrate()

  const settings = await initPrivateSettings({
    cwd: ctx.settingsPath
  }, locals)
  locals.settings = settings
}

async function initFeatureManager (ctx: MainContext, locals: Locals): Promise<void> {
  locals.featureManager = new FeatureManager(locals)
  locals.featureContext = {}
}

async function initApi (
  ctx: MainContext,
  locals: Locals
): Promise<void> {
  // Create and initialize connect manager
  const jwk = await locals.settings.get('secret') as JWK
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
async function onReady (ctx: MainContext, locals: Locals): Promise<void> {
  // Preauthentication initialization
  await initApplication(ctx, locals)
  await initActions(ctx, locals)
  await initUI(ctx, locals)
  await initVersionManager(ctx, locals)
  await initFeatureManager(ctx, locals)

  // Authentication
  await initAuth(ctx, locals)

  // Postauthentication initialization
  await initApi(ctx, locals)
  await initWalletFactory(ctx, locals)

  // Finish migration
  const { versionManager } = locals
  await versionManager.finishMigration()

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

    const locals: Locals = { packageJson } as any
    const ctx = initContext<MainContext>({
      appPath: path.resolve(__dirname, '../../'),
      settingsPath: app.getPath('userData'),
      storeMigrationProxy: createStoreMigrationProxy()
    })

    onReady(ctx, locals).catch(...handleError(locals))
  })
}
