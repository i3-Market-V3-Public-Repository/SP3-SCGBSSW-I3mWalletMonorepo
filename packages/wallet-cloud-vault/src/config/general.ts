import { existsSync } from 'fs'
import { config as loadEnvFile } from 'dotenv'
import { parseProccessEnvVar } from './parseProcessEnvVar'

if (existsSync('./.env')) loadEnvFile()

const nodeEnv = parseProccessEnvVar('NODE_ENV', { defaultValue: 'production', allowedValues: ['production', 'development'] })

export const general = {
  nodeEnv
}
