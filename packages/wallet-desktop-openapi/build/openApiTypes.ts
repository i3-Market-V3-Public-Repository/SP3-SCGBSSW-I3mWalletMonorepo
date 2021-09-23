import fs from 'fs'
import path from 'path'

import chalk from 'chalk'
import dtsGenerator, { parseSchema } from 'dtsgenerator'
import ts from 'typescript'

import pkgJson from '../package.json'

const rootDir = path.join(__dirname, '..')

const openApiJsonPath = path.join(rootDir, pkgJson.main)

const typesFilePath = path.join(rootDir, pkgJson.directories.types, 'openapi.d.ts')
const dstDir = path.dirname(typesFilePath)

const nameSpace = 'Wallet'

const generateDTS = async (): Promise<void> => {
  fs.mkdirSync(dstDir, { recursive: true })
  const spec = JSON.parse(fs.readFileSync(openApiJsonPath, 'utf-8'))
  const configFile = ts.readJsonConfigFile(path.join(rootDir, 'tsconfig.json'), (file) => fs.readFileSync(file, 'utf-8'))
  const parsedTsConfig = ts.parseJsonSourceFileConfigFileContent(configFile, ts.sys, rootDir)
  const generatedContent = await dtsGenerator({
    contents: [parseSchema(spec)],
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
    `/* eslint-disable @typescript-eslint/no-empty-interface */\n${generatedContent.replace(/; \/\//g, ' //').replace(/declare /g, '').replace(/namespace /g, 'export namespace ')}`,
    { flag: 'w' },
    (err) => {
      if (err !== null) {
        return console.trace(err)
      }
      console.log(chalk.green(`${openApiJsonPath}: TS definitions generated in -> ${typesFilePath}`))
    }
  )
}

export default generateDTS

if (require.main === module) {
  generateDTS().catch((err) => {
    console.trace(err)
  })
}
