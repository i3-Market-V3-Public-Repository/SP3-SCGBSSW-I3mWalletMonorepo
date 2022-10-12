import fs from 'fs'
import path from 'path'
import openapi from '@i3m/wallet-desktop-openapi'
import pkgJson from '../package.json'

const rootDir = path.join(__dirname, '..')
const srcDir = path.join(rootDir, pkgJson.directories.src, 'ts')

interface OpenApiMethod {
  operationId: string
  responses: {
    [key: string]: any
  }
  requestBody?: any
  parameters?: any[]
}

interface Param {
  name: string
  type: string
}
interface Method {
  tab?: number
  tabChar?: string
  visibility?: string
  name?: string
  params?: Param[]
  returnType?: string
}

function capitalize (input: string): string {
  return input[0].toUpperCase() + input.slice(1)
}

function fixClassName (name: string): string {
  const fixedName = isNaN(Number(name[0])) ? name : `$${name}`
  return capitalize(fixedName)
}

class Code {
  constructor (protected str = '') {}

  prependLine (line?: string, tab = 0, tabChar = '  '): void {
    const prevStr = this.str
    let newLine = ''
    if (line !== undefined) {
      newLine = tabChar.repeat(tab) + line
    }
    this.str = newLine + '\n' + prevStr
  }

  writeLine (line?: string, tab = 0, tabChar = '  '): void {
    if (line !== undefined) {
      this.str += tabChar.repeat(tab) + line
    }
    this.str += '\n'
  }

  replace (match: RegExp, code?: Code): void {
    const replaceText = code === undefined ? '' : code.str
    this.str = this.str.replace(match, replaceText)
  }

  save (path: string): void {
    fs.writeFileSync(path, this.str)
  }

  print (): void {
    console.log(this.str)
  }

  static fromFile (path: string): Code {
    return new Code(fs.readFileSync(path, 'utf-8'))
  }

  static fromMethods (methods: Method[], defaults?: Method): Code {
    const code = new Code()
    for (const partialMethod of methods) {
      const method: Required<Method> = Object.assign({
        tab: 0,
        visibility: '',
        tabChar: '  ',
        name: 'example',
        params: [],
        returnType: 'void'
      }, partialMethod, defaults)

      code.writeLine(
        `${method.visibility !== '' ? `${method.visibility} ` : ''}${method.name} (${method.params.map((param) => `${param.name}: ${param.type}`).join(', ')}): ${method.returnType}`,
        method.tab, method.tabChar
      )
    }

    return code
  }
}

const methodsFromOpenapi = function (): Method[] {
  // Write methods
  const methods: Method[] = []
  Object.entries(openapi.paths).forEach(([path, openapiPath]) => {
    Object.entries<OpenApiMethod>(openapiPath).forEach(([method, openapiMethod]) => {
      // Get method name
      const { operationId } = openapiMethod

      // Build return type
      const operationClass = fixClassName(operationId)
      const returnType = `Promise<${Object.keys(openapiMethod.responses)
        .filter((code) => code !== 'default')
        .map((code) => {
          const codeClass = fixClassName(code)
          return `WalletPaths.${operationClass}.Responses.${codeClass}`
        }).join(' | ')}>`

      // Build params
      const params: Param[] = []
      if (openapiMethod.parameters !== undefined) {
        let hasQueryParam = false
        let hasPathParam = false

        for (const param of openapiMethod.parameters) {
          if (!hasQueryParam && param.in === 'query') {
            hasQueryParam = true
            params.push({
              name: 'queryParameters',
              type: `WalletPaths.${operationClass}.QueryParameters`
            })
          }

          if (!hasPathParam && param.in === 'path') {
            hasPathParam = true
            params.push({
              name: 'pathParameters',
              type: `WalletPaths.${operationClass}.PathParameters`
            })
          }

          if (hasPathParam && hasQueryParam) {
            break
          }
        }
      }
      if (openapiMethod.requestBody !== undefined) {
        params.push({
          name: 'requestBody',
          type: `WalletPaths.${operationClass}.RequestBody`
        })
      }
      // funcArguments.push('dialog: Dialog')

      methods.push({
        name: operationId,
        params,
        returnType
      })
    })
  })

  return methods
}

const writeWalletCode = function (
  methods: Method[],
  dstPath: string,
  templatePath: string,
  visibility = ''
): void {
  const code = Code.fromFile(templatePath)
  const methodsCode = Code.fromMethods(methods, {
    visibility,
    tab: 1
  })

  code.prependLine('/* DO NOT MODIFY THIS FILE */')
  code.replace(/\r/g) // Remove windows CR...
  code.replace(/ *\/\/ *@ts-ignore\n/g)
  code.replace(/ *\/\/ *@wallet-methods\n/g, methodsCode)

  code.save(dstPath)
}

const walletInterfaceGenerator = function (): void {
  const methods = methodsFromOpenapi()
  // writeWalletCode(methods,
  //   path.join(srcDir, 'wallet/base-wallet.ts'),
  //   path.join(srcDir, 'wallet/base-wallet.template.ts'),
  //   'async')
  writeWalletCode(methods,
    path.join(srcDir, 'wallet/wallet.ts'),
    path.join(srcDir, 'wallet/wallet.template.ts'))
  // writeWalletCode(methods)
}

export default walletInterfaceGenerator

if (require.main === module) {
  walletInterfaceGenerator()
}
