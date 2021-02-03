'use strict'

const rollup = require('rollup')
const resolve = require('@rollup/plugin-node-resolve').nodeResolve
const replace = require('@rollup/plugin-replace')
const { terser } = require('rollup-plugin-terser')
const typescript = require('@rollup/plugin-typescript')
const ts = require('typescript')

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

if (fs.existsSync(input) !== true) {
  input = path.join(srcDir, 'index.js')
  _ts = false
}

if (fs.existsSync(input) !== true) throw new Error('You must create either index.js or index.js')

async function build ({ inputOptions, outputOptionsArray, title = '' }) {
  // create a bundle
  const bundle = await rollup.rollup(inputOptions)

  for (const outputOptions of outputOptionsArray) {
    // write the bundle to disk
    console.log(`Building ${title}\n  ⇢ ${outputOptions.file}`)
    await bundle.write(outputOptions)
  }

  // closes the bundle
  await bundle.close()
}

const buildOptionsArray = []

// Browser esm module
buildOptionsArray.push({
  title: 'Browser esm module',
  inputOptions: {
    input,
    plugins: [
      ...(_ts ? [typescript()] : []),
      replace({
        IS_BROWSER: true
      })
    ],
    external: [] // external modules here
  },
  outputOptionsArray: [
    {
      file: path.join(rootDir, pkgJson.browser),
      sourcemap: true,
      format: 'es'
    }
  ]
})

// Browser esm and iife with all dependencies bundled in
buildOptionsArray.push({
  title: 'Browser esm and iife with all dependencies bundled in',
  inputOptions: {
    input: input,
    plugins: [
      replace({
        IS_BROWSER: true
      }),
      ...(_ts ? [typescript()] : []),
      resolve({
        browser: true,
        exportConditions: ['browser', 'module', 'import', 'default']
      }),
      terser()
    ]
  },
  outputOptionsArray: [
    {
      file: path.join(dstDir, 'index.browser.bundle.iife.js'),
      format: 'iife',
      name: pkgCamelisedName
    },
    {
      file: path.join(dstDir, 'index.browser.bundle.mod.js'),
      format: 'es'
    }
  ]
})

// Node.js ESM and CJS modules
buildOptionsArray.push({
  title: 'Node.js ESM and CJS modules',
  inputOptions: {
    input,
    plugins: [
      replace({
        IS_BROWSER: false
      }),
      ...(_ts ? [typescript()] : [])
    ],
    external: [] // external modules here
  },
  outputOptionsArray: [
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
  ]
})

for (const buildOptions of buildOptionsArray) {
  build(buildOptions)
}

// Let us prepare the types file
const compilerOptions = {
  declaration: true,
  noEmit: false,
  emitDeclarationOnly: true,
  allowJs: true
}

const host = ts.createCompilerHost(compilerOptions)

const jsFile = path.join(rootDir, pkgJson.browser)
const dtsFile = path.join(rootDir, pkgJson.types)

host.writeFile = (fileName, contents) => {
  fs.writeFileSync(dtsFile, contents)
}

// Prepare and emit the d.ts files
const program = ts.createProgram([jsFile], compilerOptions, host)
program.emit()
