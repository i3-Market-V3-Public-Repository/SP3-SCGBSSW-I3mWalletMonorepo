import {
  ActionReducer,
  ApiManager,
  AsyncEventHandler,
  AuthManager,
  CloudVaultManager,
  ConnectManager,
  ElectronDialog, FeatureManager, KeysManager,
  LabeledTaskHandler,
  Locals,
  LocalsSetter,
  logger,
  MainContext,
  SharedMemoryManager,
  StoreManager, StoreMigration, TaskManager,
  ToastManager,
  Tray,
  VersionManager,
  WalletFactory,
  WindowManager
} from '@wallet/main/internal'

/**
 * Application launch events
 *
 * launch
 */

interface RuntimeEvents {
  // Launch: launch the basic modules. This phase is the fastest
  'before-launch': []
  'launch': []
  'after-launch': []

  // Start: start core funtionalities of the application
  'before-start': []
  'start': []
  'after-start': []

  // Auth: perform the local and cloud authentication
  'before-auth': [task: LabeledTaskHandler]
  'auth': [task: LabeledTaskHandler]
  'after-auth': [task: LabeledTaskHandler]

  // Load: load and migrate the stores if needed
  'private-settings': [task: LabeledTaskHandler]
  'cloud-auth': [task: LabeledTaskHandler]
  'fix-settings': [task: LabeledTaskHandler]
  'after-private-settings': [task: LabeledTaskHandler]

  'wallet-stores': [task: LabeledTaskHandler]
  'after-wallet-stores': [task: LabeledTaskHandler]

  'migration': [to: StoreMigration, task: LabeledTaskHandler]
  'after-migration': [task: LabeledTaskHandler]

  // UI: give the user free access to the ui
  'ui': []
}

export class RuntimeManager extends AsyncEventHandler<RuntimeEvents> {
  constructor (protected ctx: MainContext, protected locals: Locals, protected setLocals: LocalsSetter) {
    super()
    this.start = this.start.bind(this)
    this.auth = this.auth.bind(this)
    this.load = this.load.bind(this)
    this.ui = this.ui.bind(this)
  }

  async run (): Promise<void> {
    await this.launch()

    const { taskManager } = this.locals
    await taskManager.createTask('labeled', { title: 'Starting' }, this.start)
    await taskManager.createTask('labeled', { title: 'Authenticating' }, this.auth)
    await taskManager.createTask('labeled', { title: 'Migrating' }, this.load)
    await taskManager.createTask('labeled', { title: 'UI' }, this.ui)
  }

  async launch (): Promise<void> {
    const { ctx, locals } = this
    logger.debug('[RuntimeManager] Launch!')
    await this.emit('before-launch')

    await this.setLocals('taskManager', new TaskManager(this.locals))
    await this.setLocals('sharedMemoryManager', new SharedMemoryManager(locals))
    await this.setLocals('storeManager', new StoreManager(ctx, locals))
    await this.setLocals('actionReducer', new ActionReducer(locals))

    await this.emit('launch')
    await this.emit('after-launch')
  }

  async start (): Promise<void> {
    const { locals } = this
    logger.debug('[RuntimeManager] Start!')
    await this.emit('before-start')

    await this.setLocals('versionManager', VersionManager.initialize) // After loading public store!!
    await this.setLocals('windowManager', new WindowManager(locals))
    await this.setLocals('tray', new Tray(locals))
    await this.setLocals('dialog', new ElectronDialog(locals))
    await this.setLocals('toast', new ToastManager(locals))
    await this.setLocals('walletFactory', new WalletFactory(locals))
    await this.setLocals('featureManager', new FeatureManager(locals))
    await this.setLocals('featureContext', {})

    await this.emit('start')
    await this.emit('after-start')
  }

  async auth (task: LabeledTaskHandler): Promise<void> {
    const { ctx, locals } = this
    logger.debug('[RuntimeManager] Auth!')
    await this.setLocals('keysManager', new KeysManager(ctx, locals))
    await this.setLocals('authManager', AuthManager.initialize)
    await this.setLocals('cloudVaultManager', CloudVaultManager.initialize)

    await this.emit('before-auth', task)
    await this.emit('auth', task)
    await this.emit('after-auth', task)
  }

  async load (task: LabeledTaskHandler): Promise<void> {
    const { storeMigrationProxy } = this.ctx
    logger.debug('[RuntimeManager] Load!')

    await this.emit('private-settings', task)
    await this.emit('wallet-stores', task)
    await this.emit('cloud-auth', task)
    await this.emit('fix-settings', task)
    await this.emit('after-private-settings', task)
    await this.emit('after-wallet-stores', task)

    await this.setLocals('connectManager', ConnectManager.initialize)
    await this.setLocals('apiManager', ApiManager.initialize)

    await this.emit('migration', storeMigrationProxy.to, task)
    await this.emit('after-migration', task)
  }

  async ui (): Promise<void> {
    logger.debug('[RuntimeManager] UI!')
    await this.emit('ui')
  }
}
