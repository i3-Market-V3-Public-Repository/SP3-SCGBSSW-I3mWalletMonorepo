import { parseProccessEnvVar } from './parseProcessEnvVar'

interface CorsConfig {
  allowedOrigin: string
}

export const cors: CorsConfig = {
  allowedOrigin: parseProccessEnvVar('CORS_ACCESS_CONTROL_ALLOW_ORIGIN', { defaultValue: '*' }) as string
}
