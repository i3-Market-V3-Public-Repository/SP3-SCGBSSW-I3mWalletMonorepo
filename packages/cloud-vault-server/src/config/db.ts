import { parseProccessEnvVar } from './parseProcessEnvVar'

const storageByteLength = Number(parseProccessEnvVar('DB_STORAGE_LIMIT', 'string', { defaultValue: '5242880' }))

const storageCharLength = Math.ceil((Math.ceil(storageByteLength / 16) * 16 + 16 + 16) / 6) * 8

export const dbConfig = {
  host: parseProccessEnvVar('DB_HOST', 'string'),
  port: Number(parseProccessEnvVar('DB_PORT', 'string')),
  user: parseProccessEnvVar('DB_USER', 'string'),
  password: parseProccessEnvVar('DB_PASSWORD', 'string'),
  database: parseProccessEnvVar('DB_NAME', 'string'),
  reset: parseProccessEnvVar('DB_RESET', 'boolean', { defaultValue: false }),
  storageByteLength,
  storageCharLength
}
