import { Locals } from '@wallet/main/locals'

export const bindWithWalletFactory = async (locals: Locals): Promise<void> => {
  // Change wallet if global state changes
  const { sharedMemoryManager } = locals
  sharedMemoryManager.on('change', ({ curr, prev }) => {
    const current = curr.settings.wallet.current
    const old = prev.settings.wallet.current

    // Update current wallet
    if (current !== undefined && current !== old) {
      const { walletFactory } = locals
      walletFactory.changeWallet(current).catch((err) => {
        console.log(err)
      })
    }
  })
}
