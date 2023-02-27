
import { Toast } from '@i3m/base-wallet'
import packageJson from '../../../package.json'
import {
  Tray,
  WalletFactory,
  FeatureContext,
  SharedMemoryManager,
  WindowManager,
  ApiManager,
  FeatureManager,
  ActionReducer,
  ConnectManager,
  KeysManager,
  VersionManager,
  StoreManager,
  CloudVaultManager,
  TaskManager,
  ElectronDialog,
  AuthManager,
  WalletDesktopError,
  MainContext,
  RuntimeManager
} from '@wallet/main/internal'

export interface Locals {
  readonly packageJson: typeof packageJson

  // Application
  readonly runtimeManager: RuntimeManager
  readonly sharedMemoryManager: SharedMemoryManager
  readonly versionManager: VersionManager
  readonly storeManager: StoreManager
  readonly actionReducer: ActionReducer
  readonly taskManager: TaskManager

  // UI
  readonly tray: Tray
  readonly dialog: ElectronDialog
  readonly toast: Toast

  // Wallet
  readonly walletFactory: WalletFactory
  readonly featureManager: FeatureManager
  readonly featureContext: FeatureContext
  readonly windowManager: WindowManager
  readonly apiManager: ApiManager
  readonly cloudVaultManager: CloudVaultManager

  // Security
  readonly keysManager: KeysManager
  readonly authManager: AuthManager
  readonly connectManager: ConnectManager
}

export type LocalsKey = keyof Locals
export type PropInitializer<T> = ((ctx: MainContext, locals: Locals) => Promise<T>) | T
export type LocalsSetter = <T extends LocalsKey>(prop: T, initializer: PropInitializer<Locals[T]>) => Promise<void>

export function createLocalsProxy (ctx: MainContext): [Locals, LocalsSetter] {
  const locals: Partial<Locals> = { packageJson }
  const localsProxy = new Proxy(locals, {
    get (target, p: LocalsKey, receiver) {
      const value = target[p]
      if (value === undefined) {
        const { runtimeManager } = locals
        if (runtimeManager) {
          throw new WalletDesktopError(`Trying to get property '${p}' on runtime ${runtimeManager.current}. It will be loaded on ${runtimeManager.whenIsLoadded(p)}`)
        }
        throw new WalletDesktopError(`Trying to get property '${p}' before starting the runtime`)
      }
      return value
    },

    set (target, p: LocalsKey) {
      throw new WalletDesktopError(`Locals cannot be set! (trying to set property '${p}')`)
    }
  }) as Locals
  const setLocals: LocalsSetter = async (p, initializer) => {
    if (locals[p] !== undefined) {
      throw new WalletDesktopError(`Locals cannot be set! (trying to reset property '${p}')`)
    }

    if (typeof initializer === 'function') {
      locals[p] = await initializer(ctx, localsProxy)
    } else {
      locals[p] = initializer
    }
  }

  return [localsProxy, setLocals]
}
