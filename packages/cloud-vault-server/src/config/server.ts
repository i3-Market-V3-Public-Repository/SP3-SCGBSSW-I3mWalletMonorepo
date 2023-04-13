import { parseProccessEnvVar } from './parseProcessEnvVar'
import { isIPv6 } from 'net'

export interface ServerConfig {
  id: string
  addr: string
  port: number
  localUrl: string
  publicUrl: string
}

// export function checkIfIPv6 (str: string): boolean {
//   const regexExp = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/gi

//   return regexExp.test(str)
// }

export let serverConfig: ServerConfig
export function updateServerConfig (vars: Partial<ServerConfig>): void {
  const id = vars.id ?? parseProccessEnvVar('SERVER_ID', 'string')

  const addr = vars.addr ?? parseProccessEnvVar('SERVER_ADDRESS', 'string', { defaultValue: 'localhost' })

  const port = vars.port ?? Number(parseProccessEnvVar('SERVER_PORT', 'string', { defaultValue: '3000' }))

  const localUrl = vars.localUrl ?? `http://${isIPv6(addr) ? '[' + addr + ']' : addr}:${port}`

  const publicUrl = vars.publicUrl ?? parseProccessEnvVar('SERVER_PUBLIC_URL', 'string', { defaultValue: localUrl })

  serverConfig = {
    id,
    addr,
    port,
    localUrl,
    publicUrl
  }
}
updateServerConfig({})
