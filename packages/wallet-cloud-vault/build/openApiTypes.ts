import fs from 'fs'
import path from 'path'

import dtsGenerator, { JsonSchema, parseSchema } from 'dtsgenerator'
import ts from 'typescript'

import pkgJson from '../package.json'
import spec from '../src/spec/openapi.json'

const rootDir = path.join(__dirname, '..')

const openApiPath = path.join(rootDir, pkgJson.directories.spec, 'openapi.yaml')

const typesFilePath = path.join(rootDir, pkgJson.directories.types, 'openapi.d.ts')
const dstDir = path.dirname(typesFilePath)

const nameSpace = 'OpenApi'

const generateDTS = async (): Promise<void> => {
  fs.mkdirSync(dstDir, { recursive: true })
  const configFile = ts.readJsonConfigFile(path.join(rootDir, 'tsconfig.json'), (file) => fs.readFileSync(file, 'utf-8'))
  const parsedTsConfig = ts.parseJsonSourceFileConfigFileContent(configFile, ts.sys, rootDir)
  const generatedContent = await dtsGenerator({
    contents: [parseSchema(spec as JsonSchema)],
    config: {
      target: parsedTsConfig.options.target,
      plugins: {
        '@dtsgenerator/replace-namespace': {
          map: [
            {
              from: ['Paths'],
              to: [`${nameSpace}Paths`]
            },
            {
              from: ['Components'],
              to: [`${nameSpace}Components`]
            }
          ]
        }
      }
    }
  })
  fs.writeFile(
    typesFilePath,
    generatedContent.replace(/; \/\//g, ' //').replace(/declare /g, '').replace(/namespace /g, 'export namespace '),
    { flag: 'w' },
    (err) => {
      if (err !== null) {
        return console.trace(err)
      }
      console.info(`\x1b[32m${openApiPath}: TS definitions generated in -> ${typesFilePath}\x1b[0m`)
    }
  )
}

export default generateDTS

if (require.main === module) {
  generateDTS().catch((err) => {
    console.trace(err)
  })
}
