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
  LocalsKey,
  LocalsSetter, MainContext, PropInitializer,
  SharedMemoryManager,
  StoreManager, SynchronizationManager, TaskManager,
  ToastManager,
  Tray,
  VersionManager,
  WalletFactory,
  WindowManager
} from '@wallet/main/internal'

import { RuntimeScript } from './runtime-script'
import { migrate } from './scripts'

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
  'after-private-settings': [task: LabeledTaskHandler]
  'wallet-metadatas': [task: LabeledTaskHandler]
  'wallet-stores': [task: LabeledTaskHandler]
  'cloud-auth': [task: LabeledTaskHandler]
  'fix-settings': [task: LabeledTaskHandler]

  'after-load': [task: LabeledTaskHandler]

  'migration': [task: LabeledTaskHandler]
  'after-migration': [task: LabeledTaskHandler]

  // UI: give the user free access to the ui
  'ui': []
}

type RuntimeEvent = keyof RuntimeEvents

type ModuleRuntimes = {
  [E in LocalsKey]?: RuntimeEvent
}

export class RuntimeManager extends AsyncEventHandler<RuntimeEvents> {
  current: RuntimeEvent
  moduleRuntimes: ModuleRuntimes

  constructor (protected ctx: MainContext, protected locals: Locals, protected setLocals: LocalsSetter) {
    super()
    this.current = 'before-launch'
    this.moduleRuntimes = {}

    this.start = this.start.bind(this)
    this.auth = this.auth.bind(this)
    this.load = this.load.bind(this)
    this.ui = this.ui.bind(this)

    this.setup(this.ctx, this.locals)
  }

  setup (ctx: MainContext, locals: Locals): void {
    // ** Initializers **
    this.addLocalsModule('before-launch', [
      ['taskManager', TaskManager.initialize],
      ['sharedMemoryManager', SharedMemoryManager.initialize],
      ['storeManager', StoreManager.initialize],
      ['actionReducer', ActionReducer.initialize]
    ])

    this.addLocalsModule('before-start', [
      ['versionManager', VersionManager.initialize],
      ['windowManager', WindowManager.initialize],
      ['tray', Tray.initialize],
      ['dialog', ElectronDialog.initialize],
      ['toast', ToastManager.initialize],
      ['walletFactory', WalletFactory.initialize],
      ['featureManager', FeatureManager.initialize],
      ['featureContext', FeatureManager.initializeContext],
      ['syncManager', SynchronizationManager.initialize]
    ])

    this.addLocalsModule('after-start', [
      ['keysManager', KeysManager.initialize],
      ['authManager', AuthManager.initialize]
    ])

    this.addLocalsModule('after-private-settings', [
      ['cloudVaultManager', CloudVaultManager.initialize]
    ])

    this.addLocalsModule('after-load', [
      ['connectManager', ConnectManager.initialize],
      ['apiManager', ApiManager.initialize]
    ])

    // ** Scripts **
    this.executeScript('migration', migrate)
  }

  whenIsLoadded (prop: LocalsKey): RuntimeEvent | 'never' {
    return this.moduleRuntimes[prop] ?? 'never'
  }

  addLocalsModule <T extends LocalsKey>(evType: RuntimeEvent, initializers: Array<[prop: T, initializer: PropInitializer<Locals[T]>]>): void {
    for (const [prop] of initializers) {
      this.moduleRuntimes[prop] = evType
    }

    this.on(evType, async () => {
      for (const [prop, initializer] of initializers) {
        await this.setLocals(prop, initializer)
      }
    })
  }

  executeScript (evType: RuntimeEvent, script: RuntimeScript): void {
    this.on(evType, async () => { await script(this.ctx, this.locals) })
  }

  async emit<E extends keyof RuntimeEvents>(evType: E, ...args: RuntimeEvents[E]): Promise<void> {
    this.current = evType
    await super.emit(evType, ...args)
  }

  async run (): Promise<void> {
    await this.launch()

    const { taskManager } = this.locals
    await taskManager.createTask('labeled', { title: 'Starting', details: 'Initializing the application', freezing: true }, this.start)
    await taskManager.createTask('labeled', { title: 'Authenticating', details: 'Authenticating the user', freezing: true }, this.auth)
    await taskManager.createTask('labeled', { title: 'Loading', details: 'Loading your data', freezing: true }, this.load)
    await taskManager.createTask('labeled', { title: 'UI', details: 'Performing last UI adjustments', freezing: true }, this.ui)
  }

  async launch (): Promise<void> {
    await this.emit('before-launch')
    await this.emit('launch')
    await this.emit('after-launch')
  }

  async start (): Promise<void> {
    await this.emit('before-start')
    await this.emit('start')
    await this.emit('after-start')
  }

  async auth (task: LabeledTaskHandler): Promise<void> {
    await this.emit('before-auth', task)
    await this.emit('auth', task)
    await this.emit('after-auth', task)
  }

  async load (task: LabeledTaskHandler): Promise<void> {
    await this.emit('private-settings', task)
    await this.emit('after-private-settings', task)
    await this.emit('wallet-metadatas', task)
    await this.emit('wallet-stores', task)
    await this.emit('cloud-auth', task)
    await this.emit('fix-settings', task)
    await this.emit('after-load', task)
    await this.emit('migration', task)
    await this.emit('after-migration', task)
  }

  async ui (): Promise<void> {
    await this.emit('ui')
  }
}
