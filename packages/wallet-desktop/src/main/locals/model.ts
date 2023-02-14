
import { Dialog, Toast } from '@i3m/base-wallet'
import packageJson from '../../../package.json'
import {
  Tray,
  WalletFactory,
  FeatureContext,
  PrivateSettingsStore,
  PublicSettingsStore,
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
  TaskManager
} from '@wallet/main/internal'

export interface Locals {
  tray: Tray
  walletFactory: WalletFactory
  sharedMemoryManager: SharedMemoryManager
  settings: PrivateSettingsStore
  publicSettings: PublicSettingsStore
  windowManager: WindowManager
  apiManager: ApiManager
  featureManager: FeatureManager
  featureContext: FeatureContext
  dialog: Dialog
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
