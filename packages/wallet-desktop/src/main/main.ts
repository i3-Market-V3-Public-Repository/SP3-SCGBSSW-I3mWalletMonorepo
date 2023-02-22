import { app, dialog } from 'electron'
import path from 'path'

import { initContext } from '@wallet/lib'

import {
  createLocalsProxy,
  handlePromise,
  Locals,
  LocalsSetter,
  logger,
  MainContext,
  RuntimeManager
} from './internal'
import { createStoreMigrationProxy } from './store/migration'

// async function initAuth (ctx: MainContext, locals: Locals, task: LabeledTaskHandler): Promise<void> {

//   const { authManager } = locals
//   await authManager.authenticate(task)
//   // Cloud vault manager

//   // Authenticate
//   // await locals.authManager.authenticate()

//   //
//   // const cvmPromise = cvManagger.initialize()
//   // handlePromise(locals, cvmPromise)
// }

// async function initFeatureManager (ctx: MainContext, locals: Locals): Promise<void> {

// }

// async function initApi (
//   ctx: MainContext,
//   locals: Locals
// ): Promise<void> {
//   // Create and initialize connect manager
// }

// async function initWalletFactory (
//   ctx: MainContext,
//   locals: Locals
// ): Promise<void> {
// }

// /**
//  * Desktop Wallet startup function
//  */
// async function onReady (ctx: MainContext, locals: Locals, setLocals: LocalsSetter): Promise<void> {


  

//   // UI

//   //
//   await setLocals('featureManager', new FeatureManager(locals))
//   await setLocals('featureContext', {})

//   // Prepare the application
//   await initApplication(ctx, locals)

//   // EVENTS AUTH

//   // After auth

//   // Create and initialize api manager
//   locals.apiManager = new ApiManager(locals) // depende de connect manager
//   await locals.apiManager.initialize()


//   locals.walletFactory = new WalletFactory(locals)
//   await locals.walletFactory.initialize() // after auth


//   // Preauthentication initialization
//   const initTask: TaskDescription = { title: 'Initializing' }
//   await locals.taskManager.createTask('labeled', initTask, async () => {
//     await initActions(ctx, locals)
//     await initUI(ctx, locals)
//     await initVersionManager(ctx, locals)
//     await initFeatureManager(ctx, locals)
//     await initWalletFactory(ctx, locals)
//     await sharedMemoryBindingsBeforeAuth(locals)
//   })

//   // Authentication
//   const authTask: TaskDescription = { title: 'Authenticating' }
//   await locals.taskManager.createTask('labeled', authTask, async (task) => {
//     await initAuth(ctx, locals, task)
//   })

//   // Postauthentication initialization
//   await initApi(ctx, locals)

//   // Start application main mode
//   const { versionManager, walletFactory, windowManager } = locals
//   await versionManager.finishMigration()
//   await sharedMemoryBindingsAfterAuth(locals)
//   await walletFactory.loadCurrentWallet()

//   windowManager.openMainWindow('/wallet')
// }

async function executeRuntime(ctx: MainContext, locals: Locals, setLocals: LocalsSetter) {
  const runtimeManager = new RuntimeManager(ctx, locals, setLocals)
  await setLocals('runtimeManager', runtimeManager)
  await runtimeManager.run()
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

    const ctx = initContext<MainContext>({
      appPath: path.resolve(__dirname, '../../'),
      settingsPath: app.getPath('userData'),
      storeMigrationProxy: createStoreMigrationProxy()
    })
    const [locals, setLocals] = createLocalsProxy(ctx)
    const runtimePromise = executeRuntime(ctx, locals, setLocals)
    handlePromise(locals, runtimePromise)
  })
}
