const path = require('path')

const rollup = require('rollup')
const loadConfigFile = require('rollup/dist/loadConfigFile')

const Watcher = require('./Watcher')

const rootDir = path.join(__dirname, '../../../../')
const pkgJson = require(path.join(rootDir, 'package.json'))

let defaultTempDir
if (pkgJson.directories.tmp !== undefined) {
  defaultTempDir = path.join(rootDir, pkgJson.directories.tmp)
} else {
  defaultTempDir = path.join(rootDir, './tmp')
}

module.exports = class RollupWatcher extends Watcher {
  constructor ({ configPath = path.join(rootDir, 'rollup.config.js'), tempDir = defaultTempDir }) {
    super(path.join(tempDir, 'rollup'))
    this._error = false

    loadConfigFile(configPath).then(({ options }) => {
      this.watcher = rollup.watch(options)
      this.watcher.on('event', event => {
        this._ready = false
        if (event.code === 'START') {
          if (this.first === true) {
            console.info('\x1b[34m%s\x1b[0m [rollup] building your module...', 'ℹ')
          } else {
            console.info('\x1b[34m%s\x1b[0m [rollup] file changes detected. Rebuilding module files...', 'ℹ')
          }
          this._error = false
        } else if (event.code === 'END') {
          if (this._error === false) {
            require(path.join(rootDir, pkgJson.directories.build, 'build.dts'))
            this._ready = true
            this.emit('ready')
          } else {
            this._ready = true
          }
          this.first = false
        } else if (event.code === 'ERROR') {
          this._error = true
          console.error(event.error)
        }
      })
    }).catch((reason) => { throw new Error(reason) })
  }
}
