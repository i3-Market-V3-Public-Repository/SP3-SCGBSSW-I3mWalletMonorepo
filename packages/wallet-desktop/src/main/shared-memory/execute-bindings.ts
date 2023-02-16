import { Locals } from '@wallet/main/internal'
import { bindSettings, bindWalletFactory } from './bindings'

export const executeSharedMemoryBindings = async (locals: Locals): Promise<void> => {
  await bindSettings(locals)
  await bindWalletFactory(locals)
}
