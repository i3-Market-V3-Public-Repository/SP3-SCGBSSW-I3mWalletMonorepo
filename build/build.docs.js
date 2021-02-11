'use strict'

const fs = require('fs')
const TypeDoc = require('typedoc')
const path = require('path')
const pkgJson = require('../package.json')

const rootDir = path.join(__dirname, '..')

function camelise (str) {
  return str.replace(/-([a-z])/g,
    function (m, w) {
      return w.toUpperCase()
    })
}

async function typedoc () {
  const app = new TypeDoc.Application()

  // If you want TypeDoc to load tsconfig.json / typedoc.json files
  app.options.addReader(new TypeDoc.TSConfigReader())
  app.options.addReader(new TypeDoc.TypeDocReader())

  app.bootstrap({
    // typedoc options here
    entryPoints: ['src/index.ts'],
    plugin: ['typedoc-plugin-markdown']
  })

  const project = app.convert()

  if (project) {
    // Project may not have converted correctly
    const outputDir = 'docs'

    // Rendered docs
    await app.generateDocs(project, outputDir)
  }
}

function getRepositoryData () {
  if (typeof pkgJson.repository === 'string') {
    const repodata = pkgJson.repository.split(/[:/]/)
    const repoProvider = repodata[0]
    if (repoProvider === 'github' || repoProvider === 'gitlab' || repoProvider === 'bitbucket') {
      return {
        repoProvider,
        repoUsername: repodata[1],
        repoName: repodata[2]
      }
    } else return null
  }
}

const { repoProvider, repoUsername, repoName } = getRepositoryData() || { repoProvider: null, repoUsername: null, repoName: null }

let iifeBundle, esmBundle, workflowBadget, coverallsBadge
if (repoProvider && repoProvider === 'github') {
  iifeBundle = `[IIFE bundle](https://raw.githubusercontent.com/${repoUsername}/${repoName}/master/dist/index.browser.bundle.iife.js)`
  esmBundle = `[ESM bundle](https://raw.githubusercontent.com/${repoUsername}/${repoName}/master/dist/index.browser.bundle.mod.js)`
  workflowBadget = `[![Node CI](https://github.com/${repoUsername}/${repoName}/workflows/Node%20CI/badge.svg)](https://github.com/${repoUsername}/${repoName}/actions?query=workflow%3A%22Node+CI%22)`
  coverallsBadge = `[![Coverage Status](https://coveralls.io/repos/github/${repoUsername}/${repoName}/badge.svg?branch=master)](https://coveralls.io/github/${repoUsername}/${repoName}?branch=master)`
}

const templateFile = path.join(rootDir, pkgJson.directories.build, 'templates/readme-template.md')
let template = fs.readFileSync(templateFile, { encoding: 'UTF-8' })
  .replace(/\{\{PKG_NAME\}\}/g, pkgJson.name)
  .replace(/\{\{PKG_CAMELCASE\}\}/g, camelise(pkgJson.name))
  .replace(/\{\{IIFE_BUNDLE\}\}/g, iifeBundle || 'IIFE bundle')
  .replace(/\{\{ESM_BUNDLE\}\}/g, esmBundle || 'ESM bundle')

if (repoProvider && repoProvider === 'github') {
  template = template.replace(/\{\{GITHUB_ACTIONS_BADGES\}\}/g, workflowBadget + '\n' + coverallsBadge)
}

const readmeFile = path.join(rootDir, 'README.md')
fs.writeFileSync(readmeFile, template)

typedoc()
