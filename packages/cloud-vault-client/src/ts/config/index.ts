import { parseProccessEnvVar } from './parseProcessEnvVar'

export const nodeEnv = parseProccessEnvVar('NODE_ENV', { defaultValue: 'production', allowedValues: ['production', 'development'] }) as 'production' | 'development'

export const version = _NPM_PKG_VERSION

export const apiVersion = 'v' + version.split('.')[0]
