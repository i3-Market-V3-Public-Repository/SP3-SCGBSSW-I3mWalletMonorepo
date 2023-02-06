import { config as loadEnvFile } from 'dotenv'

loadEnvFile()

function parseEnvValue (a: string | undefined): string {
  return (a === undefined) ? '' : a
}

const invalidMsg = (varname: string, values?: string): string => {
  let ret = `Invalid value for ${varname}. `
  if (values !== undefined) ret += `Allowed values are ${values} `
  return ret
}
const booleanFalseAllowedValues = ['0', 'false', 'FALSE']
const booleanTrueAllowedValues = ['1', 'true', 'FALSE']

interface BooleanOptions {
  defaultValue: boolean
}

interface StringOptions {
  defaultValue?: string
  allowedValues?: string[]
}

export function parseProccessEnvVar (varName: string, type: 'string', options?: StringOptions): string
export function parseProccessEnvVar (varName: string, type: 'boolean', options?: BooleanOptions): boolean
export function parseProccessEnvVar (varName: string, type: 'string' | 'boolean' = 'string', options?: StringOptions | BooleanOptions): string | boolean {
  switch (type) {
    case 'string':
      return parseProccessEnvString(varName, options as StringOptions | undefined)
    case 'boolean':
      return parseProccessEnvBoolean(varName, options as BooleanOptions | undefined)
    default:
      throw new Error("type can only be 'boolean' or 'string'")
  }
}

function parseProccessEnvBoolean (varName: string, options?: BooleanOptions): boolean {
  const value = parseEnvValue(process.env[varName])
  if (value === '') {
    if (options?.defaultValue !== undefined) {
      return options.defaultValue
    } else {
      throw new Error(`Environment variable ${varName} missing and no default value provided`, { cause: 'you may need to create a .env file or pass the variables/secrets to your container' })
    }
  } else {
    if (booleanTrueAllowedValues.includes(value)) return true
    if (booleanFalseAllowedValues.includes(value)) return false
    throw new RangeError(invalidMsg(varName, booleanTrueAllowedValues.concat(booleanFalseAllowedValues).join(', ')))
  }
}

function parseProccessEnvString (varName: string, options?: StringOptions): string {
  const value = parseEnvValue(process.env[varName])
  if (value === '') {
    if (options?.defaultValue !== undefined) {
      return options.defaultValue
    } else {
      throw new Error(`Environment variable ${varName} missing and no default value provided`, { cause: 'you may need to create a .env file or pass the variables/secrets to your container' })
    }
  } else if (options?.allowedValues !== undefined && !options.allowedValues.includes(value)) {
    throw new RangeError(invalidMsg(varName, options.allowedValues.join(', ')))
  }
  return value
}
