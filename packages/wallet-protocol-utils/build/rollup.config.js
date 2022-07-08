'use strict'
const path = require('path')
const fs = require('fs')
const ts = require('typescript')

import { directories, name as _name, dependencies, peerDependencies, exports } from '../package.json'

const typescript = require('@rollup/plugin-typescript')
const resolve = require('@rollup/plugin-node-resolve').nodeResolve
const commonjs = require('@rollup/plugin-commonjs')
const css = require('rollup-plugin-import-css')
const typescript2 = require('rollup-plugin-typescript2')
// const replace = require('@rollup/plugin-replace')

function camelise (str) {
  return str.replace(/-([a-z])/g,
    function (m, w) {
      return w.toUpperCase()
    })
}

const rootDir = path.join(__dirname, '..')
const dstDir = path.join(rootDir, 'dist')


const regex = /^(?:(?<scope>@.*?)\/)?(?<name>.*)/ // We are going to take only the package name part if there is a scope, e.g. @my-org/package-name
const { name } = _name.match(regex).groups
const pkgCamelisedName = camelise(name)


const configPath = path.join(rootDir, 'tsconfig.json')
if (!configPath) {
  throw new Error("Could not find a valid 'tsconfig.json'.")
}

const compilerOptions = ts.readConfigFile(configPath, path =>
  fs.readFileSync(path).toString()).config.compilerOptions

const srcDir = path.join(rootDir, 'src')
const inputFile = path.join(srcDir, 'index.ts')

const sourcemapOutputOptions = {
  sourcemap: true,
  sourcemapPathTransform: (relativeSourcePath, sourcemapPath) => {
    // will replace relative paths with absolute paths
    const sourcePath = path.resolve(srcDir, relativeSourcePath)
    return path.relative(dstDir, sourcePath)
  }
}

module.exports = [
  { // Browser bundles
    input: inputFile,
    output: [
      // {
      //   file: path.join(dstDir, 'wallet-protocol-utils.umd.js'),
      //   name: 'walletProtocolUtils',
      //   format: 'umd',
      // },
      // ESM for browsers and declarations
      {
        file: join(rootDir, exports['.'].default),
        ...sourcemapOutputOptions,
        format: 'es'
      },

      // Browser bundles
      {
        file: path.join(dstDir, 'bundles/iife.js'),
        format: 'iife',
        name: pkgCamelisedName,
      },
      {
        file: path.join(dstDir, 'bundles/esm.js'),
        ...sourcemapOutputOptions,
        format: 'es'
      },
      {
        file: path.join(dstDir, 'bundles/esm.min.js'),
        format: 'es',
      },
      {
        file: path.join(dstDir, 'bundles/umd.js'),
        format: 'umd',
        name: pkgCamelisedName,
      },

      // Node
      {
        file: path.join(rootDir, exports['.'].node.require),
        ...sourcemapOutputOptions,
        format: 'cjs',
        exports: 'auto'
      },
      {
        file: path.join(rootDir, exports['.'].node.import),
        ...sourcemapOutputOptions,
        format: 'es'
      }
    ],
    external: ['electron'],
    plugins: [
      // replace({
      //   'process.env.NODE_ENV': process.env.NODE_ENV,
      //   preventAssignment: true
      // }),
      // typescript({
      //   ...compilerOptions
      // }),
      typescript2({
        tsconfigDefaults: compilerOptions,
        useTsconfigDeclarationDir: true
      }),
      css(),
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
