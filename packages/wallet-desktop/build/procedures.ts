import fs from 'fs-extra'
import path from 'path'

import concurrently from 'concurrently'
import rimraf from 'rimraf'
import chokidar from 'chokidar'
import { Observable } from 'rxjs'
import { tap, debounceTime } from 'rxjs/operators'

import paths from './paths'
import { ElectronDev } from './electron-dev'

export default {
  clean: async () => await new Promise<void>(resolve => {
    rimraf(paths.dist, (err) => {
      // TODO: Fix types?
      if (err) { // eslint-disable-line
        throw err
      }
      resolve()
    })
  }),

  copyResources: async () => {
    await fs.copy(paths.res, path.resolve(paths.dist, 'res'))
  },

  buildRenderer: async () => {
    await concurrently(['npm:build:renderer'])
  },

  buildSource: async ({ watch = false }) => {
    const npmMethod = watch ? 'watch' : 'build'
    await concurrently([`npm:${npmMethod}:main`, `npm:${npmMethod}:renderer`])
  },

  start: async () => {
    // Files observable
    const files$ = new Observable<string>(subscriber => {
      const watcher = chokidar.watch(paths.dist)
      watcher.on('change', (path) => {
        subscriber.next(path)
      })
      watcher.on('add', (path) => {
        subscriber.next(path)
      })
    })

    // Electron launcher
    const electron = new ElectronDev()
    await electron.init()

    files$
      .pipe(
        tap((file) => electron.notify(file)), // Notify electron dev the files that have changed
        debounceTime(500) // Time in milliseconds
      )
      .subscribe(() => {
        // Refresh the development environment
        electron.refresh()
      })
  }
}
