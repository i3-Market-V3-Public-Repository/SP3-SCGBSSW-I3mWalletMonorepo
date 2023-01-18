import { config as loadEnvFile } from 'dotenv'
import { existsSync } from 'fs'
import { parseProccessEnvVar } from './parseProcessEnvVar'

if (existsSync('./.env')) loadEnvFile()
interface ServerConfig {
  addr: string
  port: number
}
const port = Number(parseProccessEnvVar('SERVER_PORT', { defaultValue: '3000' }))

export const server: ServerConfig = {
  addr: parseProccessEnvVar('SERVER_ADDRESS', { defaultValue: '::' }) as string,
  port
}
