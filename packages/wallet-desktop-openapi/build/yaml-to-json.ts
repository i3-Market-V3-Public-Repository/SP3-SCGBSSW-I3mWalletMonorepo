import fs from 'fs'
import path from 'path'

import yaml from 'js-yaml'
import glob from 'glob'

const rootDir = path.join(__dirname, '..')

/**
 * Converts a multi file YAML OpenAPI spec to multifile JSON Schema
 *
 * @param srcDir - source dir (with YAML files)
 * @param dstDir - destination dir (with YAML files)
 */
const yamlToJson = function (srcDir: string, dstDir: string): void {
  const cwd = path.isAbsolute(srcDir) ? srcDir : path.join(rootDir, srcDir)
  const files = glob.sync('**/*.yaml', { cwd })

  if (!path.isAbsolute(dstDir)) dstDir = path.join(rootDir, dstDir)

  for (const file of files) {
    const fileParse = path.parse(file)
    const yamlFile = path.join(rootDir, 'src', file)
    const jsonFileDir = path.join(dstDir, fileParse.dir)
    const jsonFile = path.join(jsonFileDir, `${fileParse.name}.json`)
    fs.mkdirSync(jsonFileDir, { recursive: true })
    try {
      const spec = yaml.load(fs.readFileSync(yamlFile, 'utf8'))
      const specStr = JSON.stringify(spec, null, 2).replace(/\.(yaml|yml)/g, '.json')
      fs.writeFileSync(jsonFile, specStr)
    } catch (error) {
      console.log(error)
    }
  }
}

export default yamlToJson
