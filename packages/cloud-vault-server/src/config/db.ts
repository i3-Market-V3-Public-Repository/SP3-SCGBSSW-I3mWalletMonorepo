import { parseProccessEnvVar } from './parseProcessEnvVar'

export const dbConfig = {
  host: parseProccessEnvVar('DB_HOST', 'string'),
  port: Number(parseProccessEnvVar('DB_PORT', 'string')),
  user: parseProccessEnvVar('DB_USER', 'string'),
  password: parseProccessEnvVar('DB_PASSWORD', 'string'),
  database: parseProccessEnvVar('DB_NAME', 'string'),
  reset: parseProccessEnvVar('DB_RESET', 'boolean', { defaultValue: false }),
  storageLimit: Number(parseProccessEnvVar('DB_STORAGE_LIMIT', 'string', { defaultValue: '6990552' }))
}
