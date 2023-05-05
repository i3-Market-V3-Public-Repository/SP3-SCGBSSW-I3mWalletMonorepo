import { handleErrorCatch, WalletDesktopError } from '@wallet/main/errors'
import { Locals } from '@wallet/main/locals'

export const bindWithWalletFactory = async (locals: Locals): Promise<void> => {
  // Change wallet if global state changes
  const { sharedMemoryManager: shm } = locals

  shm.on('change', ({ curr, prev, ctx }) => {
    if (ctx?.modifiers?.['no-wallet-change'] === true) {
      return
    }

    const current = curr.settings.public.currentWallet
    const old = prev.settings.public.currentWallet
    const { wallets: currWallets } = curr.settings.private.wallet
    // const { wallets: prevWallets } = prev.settings.private.wallet
    // const currWalletsLength = Object.keys(currWallets).length
    // const prevWalletsLength = Object.keys(prevWallets).length

    // // A wallet has been deleted
    // if (currWalletsLength < prevWalletsLength) {
    //   if (currWalletsLength === 0) {
    //     const forceWalletPromise = walletFactory.forceOneWallet()
    //     forceWalletPromise.catch(...handleErrorCatch(locals))
    //   }
    // }

    // Update current wallet
    if (current !== undefined && current !== old) {
      const { walletFactory } = locals
      const currentWalletInfo = currWallets[current]
      if (currentWalletInfo === undefined) {
        throw new WalletDesktopError('cannot load current wallet: inconsistent data', {
          message: 'Load Wallet',
          details: 'Cannot load current wallet: inconsistent data',
          severity: 'error'
        })
      }
      walletFactory.changeWallet(currentWalletInfo).catch(...handleErrorCatch(locals))
    }
  })
}
