import fs from 'fs'
import path from 'path'

import SwaggerParser from '@apidevtools/swagger-parser'
import jsYaml from 'js-yaml'
import _ from 'lodash'
import type { OpenAPIV3 } from 'openapi-types'

import pkgJson from '../package.json'

const rootDir = path.join(__dirname, '..')

const apiVersion = `v${pkgJson.version.split('.')[0]}`

function fillWithPkgJsonData (spec: OpenAPIV3.Document): void {
  spec.info.description = pkgJson.description
  spec.info.version = apiVersion
  let licenseUrl = ''
  switch (pkgJson.license) {
    case 'EUPL':
    case 'EUPL-1':
    case 'EUPL-1.2':
      licenseUrl = 'https://joinup.ec.europa.eu/sites/default/files/custom-page/attachment/2020-03/EUPL-1.2%20EN.txt'
      break
    default:
      break
  }
  spec.info.license = { name: pkgJson.license, url: licenseUrl }
  spec.info.contact = {
    name: pkgJson.author.name,
    email: pkgJson.author.email,
    url: pkgJson.author.url
  }
  const paths: { [key: string]: any } = {}
  for (const path of Object.keys(spec.paths)) {
    const key: string = path.replace('API_VERSION', apiVersion)
    paths[key] = spec.paths[path]
  }
  spec.paths = paths
}

function fixRefs (obj: {}): void {
  for (const value of Object.values(obj)) {
    if (typeof value === 'object') {
      if ((value as any).$ref !== undefined) {
        if (Object.keys(value as any).length > 1) {
          delete (value as any).$ref
        } else {
          (value as any).$ref = (value as any).$ref.replace(/.+\.(json|yaml)#/, '#')
        }
      }
      fixRefs(value as {})
    }
  }
}

function removeIgnoredPaths (spec: OpenAPIV3.Document): void {
  delete spec.paths['/_IGNORE_PATH']
}

interface SpecBundles {
  api: OpenAPIV3.Document
  dereferencedApi: OpenAPIV3.Document
}
const bundleSpec = async function (): Promise<SpecBundles> {
  const openApiPath = path.join(rootDir, pkgJson.directories.src, 'openapi.yaml')

  const parser = new SwaggerParser()
  const rootApi = await parser.parse(openApiPath)
  const refs = (await parser.resolve(openApiPath)).values()

  const specs = []
  for (const [ref, spec] of Object.entries(refs)) {
    if (ref !== openApiPath) {
      specs.push(spec)
    }
  }
  const bundledSpec: OpenAPIV3.Document = _.defaultsDeep(rootApi, ...specs)
  removeIgnoredPaths(bundledSpec)
  fixRefs(bundledSpec)
  fillWithPkgJsonData(bundledSpec)

  const dereferencedBundledSpec = await parser.dereference(_.cloneDeep(bundledSpec)) as OpenAPIV3.Document

  await parser.validate(dereferencedBundledSpec)

  return {
    api: bundledSpec,
    dereferencedApi: dereferencedBundledSpec
  }
}

const bundle = async (): Promise<void> => {
  const jsonBundlePath = path.join(rootDir, pkgJson.exports['./openapi.json'])
  const jsonDereferencedBundlePath = path.join(rootDir, pkgJson.exports['./openapi_dereferenced.json'])
  const yamlBundlePath = path.join(rootDir, pkgJson.exports['./openapi.yaml'])

  fs.rmSync(jsonBundlePath, { force: true })
  fs.mkdirSync(path.dirname(jsonBundlePath), { recursive: true })
  fs.rmSync(jsonDereferencedBundlePath, { force: true })
  fs.mkdirSync(path.dirname(jsonDereferencedBundlePath), { recursive: true })
  fs.rmSync(yamlBundlePath, { force: true })
  fs.mkdirSync(path.dirname(yamlBundlePath), { recursive: true })

  const { api, dereferencedApi } = await bundleSpec()

  fs.writeFileSync(jsonBundlePath, JSON.stringify(api, null, 2))

  console.log('\x1b[32m%s\x1b[0m', `OpenAPI Spec JSON bundle written to -> ${jsonBundlePath}`)

  fs.writeFileSync(jsonDereferencedBundlePath, JSON.stringify(dereferencedApi, null, 2))
  console.log('\x1b[32m%s\x1b[0m', `OpenAPI Spec dereferenced JSON bundle written to -> ${jsonDereferencedBundlePath}`)

  fs.writeFileSync(yamlBundlePath, jsYaml.dump(api))

  console.log('\x1b[32m%s\x1b[0m', `OpenAPI Spec YAML bundle written to -> ${yamlBundlePath}`)
}

export default bundle

if (require.main === module) {
  bundle().catch((err) => {
    console.trace(err)
  })
}
