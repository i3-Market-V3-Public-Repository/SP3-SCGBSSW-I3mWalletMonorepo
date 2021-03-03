'use strict'

const path = require('path')
const Module = require('module')

const chai = require('chai')
const rimraf = require('rimraf')

const rootDir = path.join(__dirname, '../../../')
const pkgJson = require(path.join(rootDir, 'package.json'))

global.chai = chai

const watch = (process.argv.includes('--watch') || process.argv.includes('-w'))

const TestsBuilder = require('./builders/TestsBuilder')
const RollupBuilder = require('./builders/RollupBuilder')

let tempDir
if (pkgJson.directories.tmp !== undefined) {
  tempDir = path.join(rootDir, pkgJson.directories.tmp)
} else {
  tempDir = path.join(rootDir, './tmp')
}
const rollupBuilder = new RollupBuilder({ configPath: path.join(rootDir, 'build/rollup.config.cjs'), tempDir, watch })
const testBuilder = new TestsBuilder({ tempDir })

exports.mochaHooks = {
  beforeAll: [
    function (done) {
      // Just in case our module had been modified. Reload it when the tests are repeated (for mocha watch mode).
      delete require.cache[require.resolve(rootDir)]
      global._pkg = require(rootDir)
      done()
    },
    async function () {
      this.timeout('120000')
      await rollupBuilder.ready()
      await testBuilder.ready()
    }
  ]
}

exports.mochaGlobalSetup = function () {
  delete Module._extensions['.ts']
}

exports.mochaGlobalTeardown = function () {
  testBuilder.close()
  rollupBuilder.close()

  // I use the sync version of rimraf precisely because it blocks the
  // main thread and thus the mocha watcher, which otherwise would complain
  // about files being deleted
  rimraf.sync(tempDir, { disableGlob: true })
}
