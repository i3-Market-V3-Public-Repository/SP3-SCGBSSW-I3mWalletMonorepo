'use strict'

const resolve = require('@rollup/plugin-node-resolve').nodeResolve
const replace = require('@rollup/plugin-replace')
const { terser } = require('rollup-plugin-terser')
const typescriptPlugin = require('@rollup/plugin-typescript')
const commonjs = require('@rollup/plugin-commonjs')

const path = require('path')
const fs = require('fs')
const pkgJson = require('../package.json')

const rootDir = path.join(__dirname, '..')
const dstDir = path.join(rootDir, pkgJson.directories.dist)
const srcDir = path.join(rootDir, 'src')

function camelise (str) {
  return str.replace(/-([a-z])/g,
    function (m, w) {
      return w.toUpperCase()
    })
}

const regex = /^(?:(?<scope>@.*?)\/)?(?<name>.*)/ // We are going to take only the package name part if there is a scope, e.g. @my-org/package-name
const { name } = pkgJson.name.match(regex).groups
const pkgCamelisedName = camelise(name)

const input = path.join(srcDir, 'index.ts')
if (fs.existsSync(input) !== true) throw new Error('The entry point should be index.ts')

const tsBundleOptions = {
  exclude: ['test/**/*', 'src/**/*.spec.ts', './build/typings/global-this-pkg.d.ts']
}

const tsDeclarationOptions = {
  ...tsBundleOptions,
  declaration: true,
  outDir: dstDir,
  declarationDir: dstDir,
  declarationMap: true
}

const external = [...Object.keys(pkgJson.dependencies || {}), ...Object.keys(pkgJson.peerDependencies || {})]

const sourcemapOutputOptions = {
  sourcemap: 'inline',
  sourcemapExcludeSources: true
}

module.exports = [
  { // ESM for browsers
    input: input,
    output: [
      {
        file: path.join(rootDir, pkgJson.browser),
        ...sourcemapOutputOptions,
        format: 'es'
      }
    ],
    plugins: [
      replace({
        IS_BROWSER: true,
        preventAssignment: true
      }),
      typescriptPlugin(tsBundleOptions)
    ],
    external
  },
  { // Browser bundles
    input: input,
    output: [
      {
        file: path.join(dstDir, 'index.browser.bundle.iife.js'),
        format: 'iife',
        name: pkgCamelisedName
      },
      {
        file: path.join(dstDir, 'index.browser.bundle.mod.js'),
        format: 'es'
      }
    ],
    plugins: [
      replace({
        IS_BROWSER: true,
        preventAssignment: true
      }),
      typescriptPlugin(tsBundleOptions),
      resolve({
        browser: true,
        exportConditions: ['browser', 'module', 'import', 'default']
      }),
      terser()
    ]
  },
  { // Node ESM
    input: input,
    output: {
      dir: dstDir,
      entryFileNames: path.basename(pkgJson.module),
      ...sourcemapOutputOptions,
      format: 'cjs'
    },
    plugins: [
      replace({
        IS_BROWSER: false,
        preventAssignment: true
      }),
      typescriptPlugin(tsBundleOptions),
      commonjs({ extensions: ['.js', '.ts'] }) // the ".ts" extension is required
    ],
    external
  },
  { // Node CJS with declaration files
    input: input,
    output: {
      dir: dstDir,
      entryFileNames: path.basename(pkgJson.main),
      ...sourcemapOutputOptions,
      format: 'cjs'
    },
    plugins: [
      replace({
        IS_BROWSER: false,
        preventAssignment: true
      }),
      typescriptPlugin(tsDeclarationOptions),
      commonjs({ extensions: ['.js', '.ts'] }) // the ".ts" extension is required
    ]
  }
]
