import fs from 'fs'
import path from 'path'

import chalk from 'chalk'
import _ from 'lodash'
import SwaggerParser from '@apidevtools/swagger-parser'
import { OpenAPIV3 } from 'openapi-types'
import jsYaml from 'js-yaml'

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

const bundleSpec = async function (): Promise<OpenAPIV3.Document> {
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
  return bundledSpec
}

const bundle = async (): Promise<void> => {
  const api = await bundleSpec()

  const jsonBundle = path.join(rootDir, pkgJson.main)
  api.info.version = pkgJson.version
  fs.writeFileSync(jsonBundle, JSON.stringify(api, null, 2))
  console.log(chalk.green(`OpenAPI Spec JSON bundle written to -> ${jsonBundle}`))

  const yamlBundle = path.join(rootDir, pkgJson.exports['./openapi.yaml'])
  fs.writeFileSync(yamlBundle, jsYaml.dump(api))
  console.log(chalk.green(`OpenAPI Spec YAML bundle written to -> ${yamlBundle}`))
}

export default bundle

if (require.main === module) {
  bundle().catch((err) => {
    console.trace(err)
  })
}
