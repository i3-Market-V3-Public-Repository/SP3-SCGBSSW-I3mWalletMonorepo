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
const booleanAllowedValues = booleanFalseAllowedValues.concat(booleanTrueAllowedValues)

interface Options {
  defaultValue?: string | boolean
  allowedValues?: string[]
  isBoolean?: boolean
}

export function parseProccessEnvVar (varName: string, options?: Options): string | boolean {
  const value: string = parseEnvValue(process.env[varName])
  options = options ?? {}
  const isBoolean = options?.isBoolean ?? false
  if (isBoolean) {
    options = {
      ...options,
      allowedValues: booleanAllowedValues
    }
  }
  if (value === '') {
    if (options.defaultValue === undefined) {
      if (options.allowedValues !== undefined && !options.allowedValues.includes('')) {
        throw new RangeError(invalidMsg(varName, options.allowedValues.join(', ')))
      }
    } else {
      return options.defaultValue
    }
  }
  if (isBoolean && booleanTrueAllowedValues.includes(value)) return true
  if (isBoolean && booleanFalseAllowedValues.includes(value)) return false
  if (options.allowedValues !== undefined && !options.allowedValues.includes(value)) {
    throw new RangeError(invalidMsg(varName, options.allowedValues.join(', ')))
  }
  return value
}
