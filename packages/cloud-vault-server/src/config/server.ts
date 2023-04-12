import { parseProccessEnvVar } from './parseProcessEnvVar'

export interface ServerConfig {
  id: string
  addr: string
  port: number
  localUrl: string
  publicUrl: string
}

export function checkIfIPv6 (str: string): boolean {
  const regexExp = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/gi

  return regexExp.test(str)
}

const id = parseProccessEnvVar('SERVER_ID', 'string')

const addr = parseProccessEnvVar('SERVER_ADDRESS', 'string', { defaultValue: parseProccessEnvVar('HOSTNAME', 'string', { defaultValue: '::' }) })

const port = Number(parseProccessEnvVar('SERVER_PORT', 'string', { defaultValue: '3000' }))

const localUrl = `http://${checkIfIPv6(addr) ? '[' + addr + ']' : addr}:${port}`

const publicUrl = parseProccessEnvVar('SERVER_PUBLIC_URL', 'string', { defaultValue: localUrl })

// console.log(addr, port, url)

export const serverConfig: ServerConfig = {
  id,
  addr,
  port,
  localUrl,
  publicUrl
}
