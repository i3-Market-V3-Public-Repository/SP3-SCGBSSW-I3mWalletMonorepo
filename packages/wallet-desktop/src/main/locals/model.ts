
import { Dialog, Toast } from '@i3m/base-wallet'
import {
  Tray,
  WalletFactory,
  FeatureContext,
  Settings,
  SharedMemoryManager,
  WindowManager,
  ApiManager,
  FeatureManager,
  ActionReducer,
  ConnectManager,
  LocalAuthentication
} from '@wallet/main/internal'

export interface Locals {
  tray: Tray
  walletFactory: WalletFactory
  sharedMemoryManager: SharedMemoryManager
  settings: Settings
  windowManager: WindowManager
  apiManager: ApiManager
  featureManager: FeatureManager
  featureContext: FeatureContext
  dialog: Dialog
  toast: Toast
  actionReducer: ActionReducer
  auth: LocalAuthentication
  connectManager: ConnectManager
  password: string
}
