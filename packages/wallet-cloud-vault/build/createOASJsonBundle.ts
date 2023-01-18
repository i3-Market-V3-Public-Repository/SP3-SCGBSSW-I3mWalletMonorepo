import fs from 'fs'
import jsYaml from 'js-yaml'
import { OpenAPIV3 } from 'openapi-types'
import path from 'path'
import pkgJson from '../package.json'

const rootDir = path.join(__dirname, '..')

function fillWithPkgJsonData (spec: OpenAPIV3.Document): void {
  spec.info.description = pkgJson.description
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
}

const bundle = async (): Promise<void> => {
  const openApiPath = path.join(rootDir, pkgJson.directories['spec-src'], 'openapi.yaml')

  let oasYaml = fs.readFileSync(openApiPath, 'utf-8')
  const oas = jsYaml.load(oasYaml) as OpenAPIV3.Document

  fillWithPkgJsonData(oas)

  oasYaml = oasYaml.replace(/(^info:)([\s\S]*?)(^[a-z]+:)/gm, (match, p1: string, p2: string, p3: string) => {
    return p1 + '\n' + jsYaml.dump(oas.info).replace(/^[\w\s]/gm, '  $&') + p3
  })

  const oasJsonBundlePath = path.join(rootDir, 'src', 'spec', 'openapi.json')
  const oasJsonBundleDistPath = path.join(rootDir, pkgJson.exports['./openapi.json']) // tsc does not automatically copy .yaml to dist/spec
  fs.mkdirSync(path.dirname(oasJsonBundlePath), { recursive: true })
  fs.mkdirSync(path.dirname(oasJsonBundleDistPath), { recursive: true })

  fs.writeFileSync(oasJsonBundlePath, JSON.stringify(oas, undefined, 2))
  fs.writeFileSync(oasJsonBundleDistPath, JSON.stringify(oas, undefined, 2))

  console.info(`\x1b[32mOpenAPI Spec JSON written to -> ${oasJsonBundleDistPath}\x1b[0m`)

  const oasYamlBundlePath = path.join(rootDir, 'src', 'spec', 'openapi.yaml')
  const oasYamlBundleDistPath = path.join(rootDir, pkgJson.exports['./openapi.yaml']) // tsc does not automatically copy .yaml to dist/spec
  fs.writeFileSync(oasYamlBundlePath, oasYaml)
  fs.writeFileSync(oasYamlBundleDistPath, oasYaml)
  console.info(`\x1b[32mOpenAPI Spec YAML bundle written to -> ${oasYamlBundleDistPath}\x1b[0m`)
}

export default bundle

if (require.main === module) {
  bundle().catch((err) => {
    console.trace(err)
  })
}
