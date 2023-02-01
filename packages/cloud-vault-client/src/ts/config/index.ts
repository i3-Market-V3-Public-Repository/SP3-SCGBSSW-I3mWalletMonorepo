import { parseProccessEnvVar } from './parseProcessEnvVar'

export const nodeEnv = parseProccessEnvVar('NODE_ENV', { defaultValue: 'production', allowedValues: ['production', 'development'] }) as 'production' | 'development'

export const version = parseProccessEnvVar('npm_package_version', { defaultValue: '0.0.1' }) as string

export const apiVersion = 'v' + version[0]
