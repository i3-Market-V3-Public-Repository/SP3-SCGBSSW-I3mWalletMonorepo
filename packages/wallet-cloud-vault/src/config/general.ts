import { parseProccessEnvVar } from './parseProcessEnvVar'

const nodeEnv = parseProccessEnvVar('NODE_ENV', { defaultValue: 'production', allowedValues: ['production', 'development'] }) as string
const version = parseProccessEnvVar('npm_package_version', { defaultValue: '0.0.1' }) as string
export const general = {
  nodeEnv,
  version
}
