const path = require('path')

const rimraf = require('rimraf')

const TestsWatcher = require('./tests-watcher')
const RollupWatcher = require('./rollup-watcher')

const rootDir = path.join(__dirname, '../../../../')
const pkgJson = require(path.join(rootDir, 'package.json'))

let tempDir
if (pkgJson.directories.tmp !== undefined) {
  tempDir = path.join(rootDir, pkgJson.directories.tmp)
} else {
  tempDir = path.join(rootDir, './tmp')
}
const rollupWatcher = new RollupWatcher({ configPath: path.join(rootDir, 'build/rollup.config.js'), tempDir })
const testWatcher = new TestsWatcher({ tempDir })

exports.mochaHooks = {
  beforeAll: [
    async function () {
      this.timeout('120000')
      await rollupWatcher.ready()
      await testWatcher.ready()
    }
  ]
}

exports.mochaGlobalTeardown = async function () {
  await Promise.all([
    testWatcher.close(),
    rollupWatcher.close()
  ])
  await new Promise(resolve => {
    rimraf(tempDir, { disableGlob: true }, (error) => {
      if (error) throw error
      resolve()
    })
  })
}
