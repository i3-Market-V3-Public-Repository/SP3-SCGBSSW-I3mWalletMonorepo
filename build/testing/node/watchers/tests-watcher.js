const path = require('path')
const fs = require('fs')

const ts = require('typescript')
const JSON5 = require('json5')

const Watcher = require('./Watcher')

const rootDir = path.join(__dirname, '../../../../')
const pkgJson = require(path.join(rootDir, 'package.json'))

const formatHost = {
  getCanonicalFileName: path => path,
  getCurrentDirectory: ts.sys.getCurrentDirectory,
  getNewLine: () => ts.sys.newLine
}

let defaultTempDir
if (pkgJson.directories.tmp !== undefined) {
  defaultTempDir = path.join(rootDir, pkgJson.directories.tmp)
} else {
  defaultTempDir = path.join(rootDir, './tmp')
}

module.exports = class TestsWatcher extends Watcher {
  constructor ({ configPath = path.join(rootDir, 'tsconfig.json'), tempDir = defaultTempDir }) {
    super(path.join(tempDir, 'tests'))

    if (fs.existsSync(configPath) !== true) throw new Error(`Couldn't find a tsconfig file at ${configPath}`)

    const readFileAndMangle = (path) => { // We need to change the include or file in the original file to only compile the tests
      const fileStr = fs.readFileSync(path, 'utf8')
      const config = JSON5.parse(fileStr)
      if (config.file) delete config.file
      config.include = ['build/typings/**/*.ts', 'test/**/*.ts', 'src/**/*.spec.ts']
      return JSON.stringify(config)
    }
    const configFile = ts.readJsonConfigFile(configPath, readFileAndMangle)

    const parsedTsConfig = ts.parseJsonSourceFileConfigFileContent(configFile, ts.sys, path.dirname(configPath))

    const createProgram = ts.createSemanticDiagnosticsBuilderProgram

    const reportDiagnostic = (diagnostic) => {
      const filePath = path.relative(rootDir, diagnostic.file.fileName)
      console.error(`[Error ${diagnostic.code}]`, filePath, ':', ts.flattenDiagnosticMessageText(diagnostic.messageText, formatHost.getNewLine()))
    }

    const reportWatchStatusChanged = (diagnostic, newLine, options, errorCount) => {
      if (errorCount !== undefined) {
        this._ready = true
        this.emit('ready')
      } else {
        if (diagnostic.code === 6031) {
          console.info('\x1b[34m%s\x1b[0m [tsc] transpiling your tests...', 'ℹ')
        } else if (diagnostic.code === 6032) {
          console.info('\x1b[34m%s\x1b[0m [tsc] file changes detected. Transpiling your tests...', 'ℹ')
        }
        this._ready = false
      }
    }

    // Note that there is another overload for `createWatchCompilerHost` that takes
    // a set of root files.
    const host = ts.createWatchCompilerHost(
      parsedTsConfig.fileNames,
      {
        ...parsedTsConfig.options,
        outDir: this.tempDir,
        module: 'commonjs',
        noEmit: false,
        inlineSourceMap: true,
        noResolve: true
      },
      ts.sys,
      createProgram,
      reportDiagnostic,
      reportWatchStatusChanged
    )

    // `createWatchProgram` creates an initial program, watches files, and updates
    // the program over time.
    this.watcher = ts.createWatchProgram(host)
  }
}
