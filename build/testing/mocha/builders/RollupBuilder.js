const EventEmitter = require('events')
const fs = require('fs')
const path = require('path')

const rollup = require('rollup')
const loadConfigFile = require('rollup/dist/loadConfigFile')

const Builder = require('./Builder')

const rootDir = path.join(__dirname, '../../../../')
const pkgJson = require(path.join(rootDir, 'package.json'))

let defaultTempDir
if (pkgJson.directories.tmp !== undefined) {
  defaultTempDir = path.join(rootDir, pkgJson.directories.tmp)
} else {
  defaultTempDir = path.join(rootDir, './tmp')
}

module.exports = class RollupBuilder extends Builder {
  constructor ({ configPath = path.join(rootDir, 'rollup.config.js'), tempDir = defaultTempDir, watch = false }) {
    super(path.join(tempDir, 'rollup'))
    this._error = false

    loadConfigFile(configPath).then(({ options }) => {
      // Watch only the Node ES module (which also generates the typings)
      const rollupOptions = options.filter(bundle => {
        const file = (bundle.output[0].dir !== undefined)
          ? path.join(bundle.output[0].dir, bundle.output[0].entryFileNames)
          : bundle.output[0].file
        return file === path.join(rootDir, pkgJson.main)
      })

      this.builder = new RollupBundler(rollupOptions, watch)

      this.builder.on('event', event => {
        this.emit('busy')
        if (event.code === 'START') {
          if (this.first === true) {
            console.info('\x1b[34m%s\x1b[0m [rollup] building your module...', 'ℹ')
          } else {
            console.info('\x1b[34m%s\x1b[0m [rollup] file changes detected. Rebuilding module files...', 'ℹ')
          }
          this._error = false
        } else if (event.code === 'END') {
          if (this._error === false) {
            this.emit('ready')
          }
          this.first = false
        } else if (event.code === 'ERROR') {
          this._error = true
          console.error(event.error)
        }
        if (event.result !== undefined) {
          event.result.close()
        }
      })

      this.builder.start()
    }).catch((reason) => { throw new Error(reason) })
  }

  close () {
    this.builder.close()
  }
}

class RollupBundler extends EventEmitter {
  constructor (rollupOptions, watch = false) {
    super()
    this.rollupOptions = rollupOptions
    this.watch = watch
  }

  async start (forceBuild = false) {
    if (this.watch === true) {
      this.watcher = rollup.watch(this.rollupOptions)
      this.watcher.on('event', event => {
        this.emit('event', event)
      })
    } else {
      if (fs.existsSync(path.join(rootDir, pkgJson.main)) === false) {
        await this._bundle()
      } else {
        this.emit('event', { code: 'END' })
      }
    }
  }

  async _bundle () {
    this.emit('event', { code: 'START' })
    for (const optionsObj of this.rollupOptions) {
      const bundle = await rollup.rollup(optionsObj)
      try {
        await Promise.all(optionsObj.output.map(bundle.write))
        this.emit('event', { code: 'BUNDLE_END' })
      } catch (error) {
        this.emit('event', { code: 'ERROR' })
      }
    }
    this.emit('event', { code: 'END' })
  }

  close () {
    if (this.watcher !== undefined) this.watcher.close()
  }
}
