import { parseProccessEnvVar } from './parseProcessEnvVar'

export const dbConfig = {
  host: parseProccessEnvVar('DB_HOST') as string,
  port: Number(parseProccessEnvVar('DB_PORT')),
  user: parseProccessEnvVar('DB_USER') as string,
  password: parseProccessEnvVar('DB_PASSWORD') as string,
  database: parseProccessEnvVar('DB_NAME') as string,
  reset: parseProccessEnvVar('DB_RESET', { isBoolean: true }) as boolean
}
