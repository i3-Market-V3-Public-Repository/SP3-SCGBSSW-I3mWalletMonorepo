'use strict'

const resolve = require('@rollup/plugin-node-resolve').nodeResolve
const replace = require('@rollup/plugin-replace')
const { terser } = require('rollup-plugin-terser')
const typescript = require('@rollup/plugin-typescript')
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

const pkgName = pkgJson.name
const pkgCamelisedName = camelise(pkgName)

let _ts = true
let input = path.join(srcDir, 'index.ts')

const typescriptOptions = { exclude: ['testing/tests/**/*'] }
if (fs.existsSync(input) !== true) {
  input = path.join(srcDir, 'index.js')
  _ts = false
}

if (fs.existsSync(input) !== true) throw new Error('You must create either index.js or index.js')

module.exports = [
  { // ESM for browsers
    input: input,
    output: [
      {
        file: path.join(rootDir, pkgJson.browser),
        sourcemap: true,
        format: 'es'
      }
    ],
    plugins: [
      ...(_ts ? [typescript(typescriptOptions)] : []),
      replace({
        IS_BROWSER: true
      }),
      commonjs()
    ],
    external: [] // external modules here
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
        IS_BROWSER: true
      }),
      ...(_ts ? [typescript(typescriptOptions)] : []),
      resolve({
        browser: true,
        exportConditions: ['browser', 'module', 'import', 'default']
      }),
      commonjs(),
      terser()
    ]
  },
  { // Node
    input: input,
    output: [
      {
        file: path.join(rootDir, pkgJson.main),
        sourcemap: true,
        format: 'cjs'
      },
      {
        file: path.join(rootDir, pkgJson.module),
        sourcemap: true,
        format: 'esm'
      }
    ],
    plugins: [
      replace({
        IS_BROWSER: false
      }),
      ...(_ts ? [typescript(typescriptOptions)] : []),
      commonjs()
    ],
    external: [] // external modules here
  }
]
