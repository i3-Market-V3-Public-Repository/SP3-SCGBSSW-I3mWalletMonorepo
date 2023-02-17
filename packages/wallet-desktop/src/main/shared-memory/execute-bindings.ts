import { Locals } from '@wallet/main/internal'
import { bindDialog, bindSettings, bindTray, bindWalletFactory, bindWindowManager } from './bindings'

export const sharedMemoryBindingsAfterAuth = async (locals: Locals): Promise<void> => {
  await bindSettings(locals)
  await bindWalletFactory(locals)
}

export const sharedMemoryBindingsBeforeAuth = async (locals: Locals): Promise<void> => {
  await bindDialog(locals)
  await bindTray(locals)
  await bindWindowManager(locals)
}
