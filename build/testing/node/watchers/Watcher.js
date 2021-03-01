const EventEmitter = require('events')
const fs = require('fs')
const path = require('path')

const rimraf = require('rimraf')

module.exports = class Watcher extends EventEmitter {
  constructor (tempDir, noRerunOnFirstBuild = true) {
    super()
    this.first = true
    this.tempDir = tempDir

    try {
      fs.mkdirSync(tempDir, { recursive: true })
    } catch (error) { }
    this.semaphoreFile = path.join(tempDir, 'semaphore')

    this.on('ready', () => {
      if (this.first !== true || noRerunOnFirstBuild === false) {
        fs.writeFile(this.semaphoreFile, 'utf-8', (err) => {
          if (err) throw err
        })
      }
      this.first = false
    })

    this._ready = false
  }

  get busy () {
    return !this._ready
  }

  set busy (value) {
    this._ready = !value
  }

  ready () {
    return new Promise(resolve => {
      if (this._ready === true) return resolve()
      this.once('ready', () => {
        resolve()
      })
    })
  }

  close () {
    this.watcher.close()
  }

  cleanFiles () {
    return new Promise(resolve => {
      rimraf(this.tempDir, { disableGlob: true }, (error) => {
        if (error) throw error
        resolve()
      })
    })
  }
}
