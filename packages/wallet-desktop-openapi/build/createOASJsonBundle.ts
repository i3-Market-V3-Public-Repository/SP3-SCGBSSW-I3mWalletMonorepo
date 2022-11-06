import fs from 'fs'
import path from 'path'

import SwaggerParser from '@apidevtools/swagger-parser'
import jsYaml from 'js-yaml'
import _ from 'lodash'
import { OpenAPIV3 } from 'openapi-types'

import pkgJson from '../package.json'

// import yamlToJson from './yaml-to-json'

const rootDir = path.join(__dirname, '..')

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

// const prepareBundle = async function (): Promise<OpenAPIV3.Document> {
//   yamlToJson(path.join(rootDir, 'src'), path.join(rootDir, 'openapi'))

//   const openApiJsonPath = path.join(rootDir, 'openapi', 'openapi.json')
//   const rootApi: OpenAPIV3.Document = JSON.parse(fs.readFileSync(openApiJsonPath, 'utf-8'))

//   const parser = new SwaggerParser()
//   const refs = (await parser.resolve(openApiJsonPath)).values()

//   const specs = []
//   for (const [ref, spec] of Object.entries(refs)) {
//     if (ref !== openApiJsonPath) {
//       specs.push(spec)
//     }
//   }
//   const bundleSpec: OpenAPIV3.Document = _.defaultsDeep(rootApi, ...specs)
//   fixRefs(bundleSpec)
//   removeIgnoredPaths(bundleSpec)
//   return bundleSpec
// }

interface SpecBundles {
  api: OpenAPIV3.Document
  dereferencedApi: OpenAPIV3.Document
}
const bundleSpec = async function (): Promise<SpecBundles> {
  const openApiPath = path.join(rootDir, 'src', 'openapi.yaml')

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
  fixRefs(bundledSpec)
  removeIgnoredPaths(bundledSpec)

  const dereferencedBundledSpec = await parser.dereference(bundledSpec) as OpenAPIV3.Document

  await SwaggerParser.validate(dereferencedBundledSpec)

  return {
    api: bundledSpec,
    dereferencedApi: dereferencedBundledSpec
  }
}

const bundle = async (): Promise<void> => {
  const jsonBundlePath = path.join(rootDir, pkgJson.main)
  const jsonDereferencedBundlePath = path.join(rootDir, pkgJson.exports['./openapi.dereferenced.json'])
  const yamlBundlePath = path.join(rootDir, pkgJson.exports['./openapi.yaml'])

  fs.rmSync(jsonBundlePath, { force: true })
  fs.rmSync(jsonDereferencedBundlePath, { force: true })
  fs.rmSync(yamlBundlePath, { force: true })

  const { api, dereferencedApi } = await bundleSpec()

  api.info.version = pkgJson.version
  fs.writeFileSync(jsonBundlePath, JSON.stringify(api, null, 2))
  console.log('\x1b[32m%s\x1b[0m', `OpenAPI Spec JSON bundle written to -> ${jsonBundlePath}`)

  dereferencedApi.info.version = pkgJson.version
  fs.writeFileSync(jsonDereferencedBundlePath, JSON.stringify(api, null, 2))
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
