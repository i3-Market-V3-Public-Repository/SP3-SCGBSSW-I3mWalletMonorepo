
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
  ElectronDialog
} from '@wallet/main/internal'

export interface Locals {
  tray: Tray
  walletFactory: WalletFactory
  sharedMemoryManager: SharedMemoryManager
  // settings: PrivateSettingsStore
  // publicSettings: PublicSettingsStore
  windowManager: WindowManager
  apiManager: ApiManager
  featureManager: FeatureManager
  featureContext: FeatureContext
  dialog: ElectronDialog
  toast: Toast
  actionReducer: ActionReducer
  keysManager: KeysManager
  connectManager: ConnectManager
  password: string
  versionManager: VersionManager
  storeManager: StoreManager
  cloudVaultManager: CloudVaultManager
  taskManager: TaskManager
  packageJson: typeof packageJson
}
