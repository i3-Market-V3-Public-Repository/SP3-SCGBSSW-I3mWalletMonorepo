import path from 'path'
import electron from 'electron'
import { ChildProcess } from 'node:child_process'

import paths from './paths'

enum RefreshLevel {
  main = 2,
  renderer = 1,
  none = 0
}

export class ElectronDev {
  electronCommand: string
  electronServer: any
  electronProcess?: ChildProcess

  started: boolean
  refreshLevel: RefreshLevel

  electronDir: string
  mainDir: string
  libDir: string
  resDir: string

  constructor () {
    this.started = false
    this.refreshLevel = RefreshLevel.none

    this.electronCommand = electron as any
    this.electronDir = path.resolve(paths.root)
    this.mainDir = path.resolve(paths.dist, 'src', 'main')
    this.libDir = path.resolve(paths.dist, 'src', 'lib')
    this.resDir = path.resolve(paths.dist, 'res')
  }

  async init (): Promise<void> {
    // TODO: Replace electron connect with our own soltion as it is deprecated
    const electronConnect = require('electron-connect') // eslint-disable-line
    this.electronServer = electronConnect.server.create({
      electron,
      path: this.electronDir
    })

    // const args = ["-r process", this.electronDir, ...process.argv.slice(2)]
    // this.electronProcess = spawn(this.electronCommand, args, { })
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
    const args = process.argv.slice(2)
    console.log('Send args:', args)

    switch (this.refreshLevel) {
      case RefreshLevel.main:
        if (!this.started) {
          console.log('Start electron...')
          this.electronServer.start(args)
          this.started = true
        } else {
          console.log('Restart electron...')
          this.electronServer.restart(args)
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
