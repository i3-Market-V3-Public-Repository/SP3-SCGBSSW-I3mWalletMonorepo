import { parseProccessEnvVar } from './parseProcessEnvVar.js'

const nodeEnv = parseProccessEnvVar('NODE_ENV', 'string', { defaultValue: 'production', allowedValues: ['production', 'development'] }) as 'production' | 'development'
const version = parseProccessEnvVar('npm_package_version', 'string', { defaultValue: '0.0.1' })
export const general = {
  nodeEnv,
  version
}
