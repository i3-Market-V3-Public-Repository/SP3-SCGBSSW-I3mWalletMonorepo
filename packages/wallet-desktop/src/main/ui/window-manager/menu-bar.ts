import { resetAction } from '@wallet/lib'
import { Locals } from '@wallet/main/internal'
import { app, Menu, shell } from 'electron'

type Template = Parameters<(typeof Menu.buildFromTemplate)>[0]

export const buildMenuBar = (locals: Locals): Menu => {
  const template: Template = [
    {
      label: 'File',
      submenu: [
        {
          label: 'Reset',
          click: async () => await locals.actionReducer.reduce(resetAction.create())
        },
        {
          type: 'separator'
        },
        {
          label: 'Close',
          accelerator: 'CommandOrControl+W',
          role: 'close'
        }
      ]
    },
    {
      label: 'Edit',
      submenu: [
        {
          label: 'Undo',
          accelerator: 'CommandOrControl+Z',
          role: 'undo'
        },
        {
          label: 'Redo',
          accelerator: 'Shift+CommandOrControl+Z',
          role: 'redo'
        },
        { type: 'separator' },
        {
          label: 'Cut',
          accelerator: 'CommandOrControl+X',
          role: 'cut'
        },
        {
          label: 'Copy',
          accelerator: 'CommandOrControl+C',
          role: 'copy'
        },
        {
          label: 'Paste',
          accelerator: 'CommandOrControl+V',
          role: 'paste'
        },
        {
          label: 'Select All',
          accelerator: 'CommandOrControl+A',
          role: 'selectAll'
        }
      ]
    },
    {
      label: 'Window',
      submenu: [
        {
          label: 'Minimize',
          accelerator: 'CommandOrControl+M',
          role: 'minimize'
        }
      ]
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'Latest version',
          click: async () => {
            await shell.openExternal('https://github.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/releases/latest')
          }
        },
        {
          label: 'Documentation',
          click: async () => {
            await shell.openExternal('https://github.com/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/tree/public/packages/wallet-desktop')
          }
        },
        { type: 'separator' },
        {
          label: 'About',
          click: async () => {
            await locals.toast.show({ message: `Version: ${locals.packageJson.version}` })
          }
        }
      ]
    }
  ]

  if (process.platform === 'darwin') {
    const name = app.getName()
    template.unshift({ label: name })
  }

  return Menu.buildFromTemplate(template)
}
