import { app, Tray as ElectronTray, Menu } from 'electron'
import { MenuItemConstructorOptions } from 'electron/main'

import { selectWalletAction } from '@wallet/lib'

import { getResourcePath, Locals } from '@wallet/main/internal'

interface WalletItem {
  name: string
}

export class Tray {
  private readonly tray: ElectronTray
  private readonly iconPath: string

  constructor (protected locals: Locals) {
    this.iconPath = getResourcePath('img/tray.png')
    const { sharedMemoryManager } = locals
    sharedMemoryManager.on('change', (sharedMemory) => {
      const wallets: WalletItem[] = Object
        .keys(sharedMemory.settings.wallet.wallets)
        .map(name => ({ name }))

      this.updateContextMenu(wallets)
    })

    this.tray = new ElectronTray(this.iconPath)
    this.tray.setToolTip('i3Market wallet')
    this.updateContextMenu([])
  }

  updateContextMenu (wallets: WalletItem[]): void {
    const { windowManager, sharedMemoryManager, actionReducer } = this.locals
    const currentWallet = sharedMemoryManager.memory.settings.wallet.current

    const contextMenu = Menu.buildFromTemplate([
      { label: 'Open', type: 'normal', click: () => windowManager.openMainWindow() },
      {
        label: 'Wallet',
        type: 'submenu',
        enabled: wallets.length > 0,
        submenu:
          wallets.map<MenuItemConstructorOptions>(walletInfo => ({
            label: walletInfo.name,
            type: 'radio',
            checked: currentWallet === walletInfo.name,
            click: async () => {
              await actionReducer.reduce(selectWalletAction.create(walletInfo.name))
            }
          }))
      },
      {
        label: 'Close',
        type: 'normal',
        click: () => {
          windowManager.closeAllWindow()
          app.quit()
        }
      }
    ])
    this.tray.setContextMenu(contextMenu)
  }
}
