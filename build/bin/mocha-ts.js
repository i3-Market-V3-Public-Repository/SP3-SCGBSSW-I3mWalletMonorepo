#! /usr/bin/env node
const path = require('path')
const rootDir = path.join(__dirname, '../..')
const pkgJson = require(path.join(rootDir, 'package.json'))
const minimatch = require('minimatch')
const glob = require('glob')

const childProcess = require('child_process')

const args = process.argv.slice(2).map(arg => {
  const filenames = glob.sync(arg, { cwd: rootDir, matchBase: true })
  if (filenames.length > 0) {
    return filenames.map(file => {
      const isTsTestFile = minimatch(file, '{test/**/*.ts,src/**/*.spec.ts}', { matchBase: true })
      if (isTsTestFile) {
        return path.relative(rootDir, `${pkgJson.directories.tmp}/tests/${file.slice(0, -3)}.js`)
      }
      return file
    })
  }
  return arg
})

const processedArgs = []

for (const arg of args) {
  if (Array.isArray(arg)) {
    processedArgs.push(...arg)
  } else {
    processedArgs.push(arg)
  }
}
// Now we can run a script and invoke a callback when complete, e.g.
runScript(path.join(rootDir, 'node_modules/.bin/mocha'), processedArgs, function (err) {
  if (err) throw err
})

function runScript (scriptPath, args, callback) {
  // keep track of whether callback has been invoked to prevent multiple invocations
  let invoked = false

  const process = childProcess.fork(scriptPath, args)

  // listen for errors as they may prevent the exit event from firing
  process.on('error', function (err) {
    if (invoked) return
    invoked = true
    callback(err)
  })

  // execute the callback once the process has finished running
  process.on('exit', function (code) {
    if (invoked) return
    invoked = true
    var err = code === 0 ? null : new Error('exit code ' + code)
    callback(err)
  })
}
