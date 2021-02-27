const fs = require('fs')
const ts = require('typescript')
const path = require('path')
const pkgJson = require('../package.json')

const rootDir = path.join(__dirname, '..')
const inputFile = path.join(rootDir, pkgJson.directories.src, 'index.ts')
if (fs.existsSync(inputFile) !== true) throw new Error('The entry point should be index.ts')

const dtsFile = path.join(rootDir, pkgJson.types)

const configPath = path.join(rootDir, 'tsconfig.json')
if (!configPath) {
  throw new Error(`Could not find a valid 'tsconfig.json' in ${rootDir}`)
}

const compilerOptions = ts.readConfigFile(configPath, path => fs.readFileSync(path).toString()).config.compilerOptions
compilerOptions.declaration = true
compilerOptions.emitDeclarationOnly = true
compilerOptions.outDir = path.dirname(dtsFile)
compilerOptions.moduleResolution = undefined

const host = ts.createCompilerHost(compilerOptions)

// Prepare and emit the d.ts files
const program = ts.createProgram([inputFile], compilerOptions, host)
program.emit()
