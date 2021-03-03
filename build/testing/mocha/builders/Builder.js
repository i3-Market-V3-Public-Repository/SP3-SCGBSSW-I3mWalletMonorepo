const EventEmitter = require('events')
const fs = require('fs')
const path = require('path')

const rimraf = require('rimraf')

module.exports = class Builder extends EventEmitter {
  constructor (tempDir, noRerunOnFirstBuild = true) {
    super()
    this.first = true
    this._ready = false
    this.tempDir = tempDir

    try {
      fs.mkdirSync(tempDir, { recursive: true })
    } catch (error) { }
    this.semaphoreFile = path.join(tempDir, 'semaphore')

    this.on('ready', () => {
      this._ready = true
      if (this.first !== true || noRerunOnFirstBuild === false) {
        fs.writeFile(this.semaphoreFile, 'utf-8', (err) => {
          if (err) throw err
        })
      }
      this.first = false
    })

    this.on('busy', () => {
      this._ready = false
    })
  }

  ready () {
    return new Promise(resolve => {
      if (this._ready === true) return resolve()
      this.once('ready', () => {
        resolve()
      })
    })
  }

  async close () {
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
