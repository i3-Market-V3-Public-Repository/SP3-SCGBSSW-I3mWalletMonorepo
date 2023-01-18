import { parseProccessEnvVar } from './parseProcessEnvVar'

interface ServerConfig {
  addr: string
  port: number
}
const port = Number(parseProccessEnvVar('SERVER_PORT', { defaultValue: '3000' }))

export const server: ServerConfig = {
  addr: parseProccessEnvVar('SERVER_ADDRESS', { defaultValue: '::' }) as string,
  port
}
