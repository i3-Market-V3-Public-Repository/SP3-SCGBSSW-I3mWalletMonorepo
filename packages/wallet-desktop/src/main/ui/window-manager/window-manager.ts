import { BrowserWindow, Menu } from 'electron'
import path from 'path'

import { WindowArgs } from '@wallet/lib'
import { getResourcePath, logger, Locals } from '@wallet/main/internal'
import { CustomWindow, Mapper } from './custom-window'
import { buildMenuBar } from './menu-bar'
import { MainWindow } from './main-window'

export class WindowManager {
  windows: Map<string, CustomWindow>

  constructor (protected locals: Locals) {
    // Setup menu bar
    const menuBar = buildMenuBar(locals)
    Menu.setApplicationMenu(menuBar)

    this.windows = new Map()
  }

  convertToArgs (args: WindowArgs): string {
    const json = JSON.stringify(args)
    return `--args=${Buffer.from(json).toString('base64')}`
  }

  defaultMapper: Mapper<any> = (a) => a

  createWindow (args: WindowArgs, creationArgs: Electron.BrowserWindowConstructorOptions = {}): CustomWindow {
    logger.debug(`Create a new window with name: ${args.name}`)
    return new CustomWindow(this.locals, {
      height: 600,
      width: 800,
      webPreferences: {
        preload: path.join(__dirname, 'preload.js'),
        additionalArguments: [this.convertToArgs(args)],
        contextIsolation: false,
        nodeIntegration: true
      },
      ...creationArgs
    })
  }

  createDialog (args: WindowArgs, creationArgs: Electron.BrowserWindowConstructorOptions = {}): CustomWindow {
    logger.debug(`Create a new dialog with name: ${args.name}`)

    const dialog = new CustomWindow(this.locals, {
      height: 300,
      width: 400,
      titleBarStyle: 'hidden',
      frame: false,
      resizable: false,
      hasShadow: false,
      webPreferences: {
        preload: path.join(__dirname, 'preload.js'),
        additionalArguments: [this.convertToArgs(args)],
        contextIsolation: false,
        nodeIntegration: true
      },
      ...creationArgs
    })
    return dialog
  }

  initWindow (window: BrowserWindow): void {
    // and load the index.html of the app.
    logger.debug(`Initialize window with id ${window.id}`)
    const indexPath = getResourcePath('index.html')
    window.loadFile(indexPath).catch((err) => {
      if (err instanceof Error) {
        throw err
      } else {
        throw new Error(`Cannot load page: ${indexPath}`)
      }
    })

    // Open the DevTools.
    if (process.env.NODE_ENV === 'development') {
      window.webContents.openDevTools()
    }
  }

  protected openWindow (windowArgs: WindowArgs): CustomWindow {
    const name = windowArgs.name
    let window = this.windows.get(name)
    if (window !== undefined) {
      window.focus()
      return window
    }

    // Create the browser window.
    window = this.createWindow(windowArgs)
    this.initWindow(window)

    this.windows.set(name, window)
    window.on('close', () => {
      this.windows.delete(name)
    })

    return window
  }

  openMainWindow = (path?: string): MainWindow => {
    let window = this.getWindow('Main')
    if (window === undefined) {
      window = this.openWindow({
        name: 'Main',
        path: path ?? 'wallet'
      }) as MainWindow
    } else if (path !== undefined) {
      window.input$.next({
        type: 'navigate',
        path
      })
    }

    return window
  }

  openSignWindow = (accountId: string): CustomWindow => this.openWindow({
    name: 'Sign',
    accountId
  })

  openPasswordDialog (): CustomWindow {
    // Create the browser window.
    const passwordDialog = this.createDialog({
      name: 'Password'
    })
    this.initWindow(passwordDialog)

    return passwordDialog
  }

  getWindow (name: 'Main'): MainWindow | undefined;
  getWindow (name: string): CustomWindow<any> | undefined {
    return this.windows.get(name)
  }

  closeAllWindow (): void {
    logger.debug('Close all windows')
    for (const [, window] of this.windows) {
      window.close()
    }
    this.windows.clear()
  }
}
