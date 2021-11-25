'use strict'
const path = require('path')
const fs = require('fs')
const ts = require('typescript')

const typescript = require('@rollup/plugin-typescript')
const resolve = require('@rollup/plugin-node-resolve').nodeResolve
const commonjs = require('@rollup/plugin-commonjs')
// const replace = require('@rollup/plugin-replace')

const rootDir = path.join(__dirname, '..')
const dstDir = path.join(rootDir, 'dist')

const configPath = path.join(rootDir, 'tsconfig.json')
if (!configPath) {
  throw new Error("Could not find a valid 'tsconfig.json'.")
}

const compilerOptions = ts.readConfigFile(configPath, path =>
  fs.readFileSync(path).toString()).config.compilerOptions

const srcDir = path.join(rootDir, 'src')
const inputFile = path.join(srcDir, 'index.ts')

module.exports = [
  { // Browser bundles
    input: inputFile,
    output: [
      {
        file: path.join(dstDir, 'wallet-connector.js'),
        format: 'es',
        sourcemap: true,
        sourcemapPathTransform: (relativeSourcePath, sourcemapPath) => {
          // will replace relative paths with absolute paths
          const sourcePath = path.resolve(srcDir, relativeSourcePath)
          return path.relative(dstDir, sourcePath)
        }
      }
    ],
    external: ['electron'],
    plugins: [
      // replace({
      //   'process.env.NODE_ENV': process.env.NODE_ENV,
      //   preventAssignment: true
      // }),
      typescript({
        ...compilerOptions
      }),
      resolve({
        browser: true,
        preferBuiltins: true,
        exportConditions: ['browser', 'module', 'import', 'default']
      }),
      commonjs()
    ],
    watch: {
      exclude: ['node_modules/**']
    }
  }
]
