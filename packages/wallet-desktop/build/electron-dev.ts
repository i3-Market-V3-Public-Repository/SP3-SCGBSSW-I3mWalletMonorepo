import path from 'path'
import electron from 'electron'

import paths from './paths'

enum RefreshLevel {
  main = 2,
  renderer = 1,
  none = 0
}

export class ElectronDev {
  electronServer: any

  started: boolean
  refreshLevel: RefreshLevel

  mainDir: string
  libDir: string
  resDir: string

  constructor () {
    this.started = false
    this.refreshLevel = RefreshLevel.none

    this.mainDir = path.resolve(paths.dist, 'src', 'main')
    this.libDir = path.resolve(paths.dist, 'src', 'lib')
    this.resDir = path.resolve(paths.dist, 'res')
  }

  async init (): Promise<void> {
    const electronConnect = require('electron-connect') // eslint-disable-line
    this.electronServer = electronConnect.server.create({
      electron,
      path: this.mainDir
    })
  }

  notify (file: string): void {
    const refreshLevel = this.computeRefreshLevel(file)
    if (refreshLevel > this.refreshLevel) {
      this.refreshLevel = refreshLevel
    }
  }

  computeRefreshLevel (file: string): RefreshLevel {
    if (file.startsWith(this.resDir)) {
      return RefreshLevel.renderer
    } else if (file.startsWith(this.mainDir) || file.startsWith(this.libDir)) {
      return RefreshLevel.main
    } else {
      return RefreshLevel.renderer
    }
  }

  refresh (): void {
    switch (this.refreshLevel) {
      case RefreshLevel.main:
        if (!this.started) {
          console.log('Start electron...')
          this.electronServer.start()
          this.started = true
        } else {
          console.log('Restart electron...')
          this.electronServer.restart()
        }
        break

      case RefreshLevel.renderer:
        if (this.started) {
          console.log('Reload electron...')
          this.electronServer.reload()
        }
        break
    }

    this.refreshLevel = RefreshLevel.none
  }

  close (): void {
    this.electronServer.stop()
  }
}
