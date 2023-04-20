import { parseProccessEnvVar } from './parseProcessEnvVar'

const nodeEnv = parseProccessEnvVar('NODE_ENV', 'string', { defaultValue: 'production', allowedValues: ['production', 'development'] }) as 'production' | 'development'
const version = '{{VERSION}}'
export const general = {
  nodeEnv,
  version
}
