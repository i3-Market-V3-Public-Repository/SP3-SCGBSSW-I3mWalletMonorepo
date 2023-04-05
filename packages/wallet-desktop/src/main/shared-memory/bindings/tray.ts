import { Locals, WalletItem } from '@wallet/main/internal'

export const bindWithTray = async (locals: Locals): Promise<void> => {
  const { sharedMemoryManager, tray } = locals
  sharedMemoryManager.on('change', ({ curr: mem }) => {
    const wallets: WalletItem[] = Object
      .keys(mem.settings.private.wallet.wallets)
      .map(name => ({ name }))

    tray.updateContextMenu(wallets)
  })
}
