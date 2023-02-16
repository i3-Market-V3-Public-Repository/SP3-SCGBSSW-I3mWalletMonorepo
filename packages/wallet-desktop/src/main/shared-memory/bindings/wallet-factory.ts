import { Locals } from '@wallet/main/locals'

export const bindWalletFactory = async (locals: Locals): Promise<void> => {
  // Change wallet if global state changes
  const { sharedMemoryManager } = locals
  sharedMemoryManager.on('change', (mem, oldMem) => {
    const current = mem.settings.wallet.current
    const old = oldMem.settings.wallet.current

    // Update current wallet
    if (current !== undefined && current !== old) {
      const { walletFactory } = locals
      walletFactory.changeWallet(current).catch((err) => {
        console.log(err)
      })
    }
  })
}
